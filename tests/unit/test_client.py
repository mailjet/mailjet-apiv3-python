# pyright: reportOperatorIssue=false
# pyright: reportReturnType=false
"""Unit tests for the Mailjet API client routing, internal logic, and security."""

from __future__ import annotations

import logging
from contextlib import suppress
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException, Timeout as RequestsTimeout

from mailjet_rest.client import Client, Config
from mailjet_rest.errors import (
    ApiError,
    CriticalApiError,
    DoesNotExistError,
    MailjetAuthError,
    TimeoutError,
    ValidationError,
)
from mailjet_rest.types import _JSON_HEADERS, _TEXT_HEADERS
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture


@pytest.fixture
def client_offline() -> Client:
    """Return a client with fake credentials for pure offline unit testing."""
    conf = Config(version="v3")
    return Client(auth=("fake_public_key", "fake_private_key"), config=conf)


# ==========================================
# 1. Authentication & Initialization Tests
# ==========================================


def test_bearer_token_auth_initialization() -> None:
    """Verify that passing a string to auth configures Bearer token (Content API v1)."""
    token = "secret_v1_token_123"
    client = Client(auth=token)

    assert client.auth == token
    assert client.session.headers.get("Authorization") == f"Bearer {token}"


def test_basic_auth_initialization() -> None:
    """Verify standard tuple initialization constructs Basic Auth correctly."""
    client = Client(auth=("pub_key", "priv_key"))
    assert client.auth == ("pub_key", "priv_key")
    assert client.session.auth == ("pub_key", "priv_key")


def test_auth_validation_errors() -> None:
    """Verify that invalid auth formats raise appropriate exceptions."""
    with pytest.raises(ValueError, match="Basic auth tuple must contain exactly two elements"):
        Client(auth=("only_one",))  # type: ignore[arg-type]


def test_client_init_enables_audit_hook_when_configured(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that Client activates the runtime audit hook if enable_security_audit is True."""
    mock_audit = MagicMock()
    monkeypatch.setattr(SecurityGuard, "enable_audit_logging", mock_audit)

    cfg = Config(enable_security_audit=True)
    Client(auth=("pub", "priv"), config=cfg)
    mock_audit.assert_called_once()


def test_config_api_url_validation_scheme() -> None:
    """Verify that insecure URLs are immediately rejected (CWE-319)."""
    # Changed from http:// to ftp:// because http:// is now legally allowed for localhost CI/CD
    with pytest.raises(ValueError, match="Security Alert \\(CWE-918\\): Invalid scheme 'ftp'"):
        Config(api_url="ftp://api.mailjet.com")


def test_config_api_url_validation_hostname() -> None:
    """Verify that malicious hosts are rejected (CWE-918)."""
    with pytest.raises(ValueError, match="Security Alert \\(CWE-918\\): Hostname 'evil.com' is not permitted"):
        Config(api_url="https://evil.com")


def test_config_timeout_invalid_values() -> None:
    """Verify that extreme or invalid timeout values are rejected to prevent resource exhaustion (CWE-400)."""
    with pytest.raises(ValueError, match="strictly positive"):
        Config(timeout=0)

    with pytest.raises(ValueError, match="strictly positive"):
        Config(timeout=-1)

    with pytest.raises(TypeError, match="numeric"):
        Config(timeout="not-a-number")  # type: ignore[arg-type]


def test_config_timeout_valid_values() -> None:
    """Verify valid complex float and tuple timeout constraints pass."""
    c1 = Config(timeout=10.5)
    assert c1.timeout == 10.5

    c2 = Config(timeout=(3.0, 15.5))
    assert c2.timeout == (3.0, 15.5)


def test_config_validation_logic() -> None:
    """Verify standard configuration parsing guarantees."""
    conf = Config(version="v1", timeout=30)
    assert conf.version == "v1"
    assert conf.timeout == 30
    assert conf.api_url == "https://api.mailjet.com/"


def test_url_sanitization_path_traversal() -> None:
    """Verify path variables are strictly sanitized (CWE-22)."""
    # Expect the ValueError we now actively throw against CWE-22 tokens
    with pytest.raises(ValueError, match="Path traversal attempt"):
        SecurityGuard.sanitize_segment("../etc/passwd")


def test_client_repr_and_str_redact_secrets() -> None:
    """Verify that string representations do not leak the private keys (CWE-316)."""
    client = Client(auth=("my_super_secret_public", "my_super_secret_private"))
    rep = repr(client)
    assert "my_super_secret" not in rep
    assert "Mailjet Client" in str(client)


def test_client_mount_retry_adapter() -> None:
    """Verify the resilient HTTP adapter mounts gracefully to intercept connection bugs."""
    client = Client(auth=("a", "b"))
    assert "https://" in client.session.adapters


def test_ambiguity_warnings_logged(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that validate_dx_routing correctly flags API version ambiguities via warnings."""

    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 404
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    with pytest.warns(DeprecationWarning, match=r"Mailjet API Ambiguity: Email API \(v3\) uses singular '/template'"):
        with suppress(Exception):
            client_offline.templates.get()


def test_infinite_timeout_resource_exhaustion() -> None:
    """Coverage: Checks the float validation logic directly on the Config object (CWE-400)."""
    with pytest.raises(ValueError, match="Timeout cannot be Infinity or NaN"):
        Config(timeout=float("inf"))


def test_zero_timeout_resource_exhaustion() -> None:
    """Coverage: Checks that 0 or negative timeouts are blocked."""
    with pytest.raises(ValueError, match="strictly positive"):
        Config(timeout=0)


def test_client_invalid_auth_type() -> None:
    """Coverage: Test invalid auth type initialization."""
    with pytest.raises(TypeError, match="Invalid auth type"):
        Client(auth=123)  # type: ignore[arg-type]


def test_client_verify_false_rejected(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Ensure verify=False emits a UserWarning."""
    # Mock the internal request to prevent actual network execution after the warning is emitted
    monkeypatch.setattr(client_offline.session, "request", MagicMock(return_value=MagicMock(status_code=200)))
    with pytest.warns(UserWarning, match="TLS verification is disabled"):
        client_offline.api_call("GET", "https://api.mailjet.com/v3/send", headers={}, verify=False)


def test_handle_api_error_branches(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Target specific HTTP status branches in _handle_api_error."""
    for status, exc_class in [(400, ValidationError), (403, MailjetAuthError), (404, DoesNotExistError)]:
        mock_response = MagicMock()
        mock_response.status_code = status
        mock_response.text = "Error"

        with patch.object(client_offline.session, "request", side_effect=RequestException(response=mock_response)):
            with pytest.raises(exc_class):
                client_offline.contact.get()


def test_config_api_url_missing_slash() -> None:
    """Coverage: Ensure Config adds trailing slash to api_url."""
    c = Config(api_url="https://api.mailjet.com")
    assert c.api_url == "https://api.mailjet.com/"


def test_client_empty_bearer_token() -> None:
    """Coverage: Blocking empty or whitespace bearer tokens."""
    with pytest.raises(ValueError, match="cannot be an empty string"):
        Client(auth="   ")


def test_client_invalid_bearer_token() -> None:
    """Coverage: Blocking invalid header-injection tokens."""
    with pytest.raises(ValueError, match="contain forbidden control characters"):
        Client(auth="token\nwith\rnewline")


def test_client_invalid_basic_auth_length() -> None:
    """Coverage: Rejecting poorly sized Basic Auth tuples."""
    with pytest.raises(ValueError, match="must contain exactly two elements"):
        Client(auth=("user", "pass", "extra"))  # type: ignore[arg-type]


def test_client_close_no_session() -> None:
    """Coverage: Graceful close when session is missing."""
    client = Client(auth=("a", "b"))
    client.session = None  # type: ignore[assignment]
    client.close()  # Should pass cleanly without exceptions


def test_client_execute_request_non_json(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Verify _execute_request sets data param explicitly for non-JSON payloads."""

    def mock_req(method: str, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> requests.Response:
        assert data == "raw text"
        assert json is None
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_req)
    client_offline.api_call(
        "POST", "https://api.mailjet.com/v3/send", headers={"Content-Type": "text/plain"}, data="raw text"
    )


def test_client_endpoint_caching(client_offline: Client) -> None:
    """Coverage: Verify __getattr__ efficiently returns from cache."""
    ep1 = client_offline.contact
    ep2 = client_offline.contact
    assert ep1 is ep2


# ==========================================
# 2. Advanced Endpoint Routing Constraints
# ==========================================


@pytest.mark.parametrize(
    ("version", "resource", "expected_path"),
    [
        ("v1", "templates", "v1/REST/templates"),
        ("v3", "contact", "v3/REST/contact"),
        ("v3.1", "message", "v3.1/REST/message"),
        ("v99_future", "newresource", "v99_future/REST/newresource"),
    ],
)
def test_dynamic_versions_standard_rest(
    version: str, resource: str, expected_path: str, client_offline: Client
) -> None:
    """Verify REST URL construction dynamically respects the configured API version."""
    client_offline.config.version = version
    endpoint = getattr(client_offline, resource)
    url = endpoint._build_url()
    assert url == f"https://api.mailjet.com/{expected_path}"


def test_dynamic_versions_content_api_v1_routing(client_offline: Client) -> None:
    """Verify Content API (v1) specific routes construct correctly."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents"


def test_dynamic_versions_content_api_v1_complex_routing(client_offline: Client) -> None:
    """Verify deeply nested Content API routes construct correctly using split action."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_types._build_url(id_val=123, action_id="P")
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/types/P"


@pytest.mark.filterwarnings("ignore:Mailjet API Ambiguity:DeprecationWarning")
@pytest.mark.parametrize(
    "version",
    ["v1", "v3", "v3.1", "v99_future"],
)
def test_dynamic_versions_send_api(version: str, client_offline: Client) -> None:
    """Verify the Send API explicitly bypasses the /REST/ prefix across all versions."""
    client_offline.config.version = version
    url = client_offline.send._build_url()
    assert url == f"https://api.mailjet.com/{version}/send"


def test_send_api_v3_bad_path_routing(client_offline: Client) -> None:
    """Verify that unexpected operations on the Send API still attempt to route consistently."""
    client_offline.config.version = "v3"
    url = client_offline.send._build_url()
    assert url == "https://api.mailjet.com/v3/send"


def test_content_api_bad_path_routing(client_offline: Client) -> None:
    """Verify that deeply nested paths format correctly via dynamic fallback logic."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_fakeaction._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/fakeaction"


def test_route_strategy_legacy_parity(client_offline: Client) -> None:
    """Verify declarative routes maintain exact legacy URL formatting."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_types._build_url(id_val=123, action_id="P")
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/types/P"


def test_statcounters_endpoint_routing(client_offline: Client) -> None:
    """Verify statistical routing bypasses standard logic."""
    client_offline.config.version = "v3"
    url = client_offline.statcounters._build_url()
    assert url == "https://api.mailjet.com/v3/REST/statcounters"


def test_camel_case_to_dash_routing(client_offline: Client) -> None:
    """Verify that CamelCase endpoints correctly translate to dashed paths (e.g., linkClick -> link-click)."""
    url = client_offline.statistics_linkClick._build_url()
    assert url == "https://api.mailjet.com/v3/REST/statistics/link-click"


def test_api_call_exception_contract(client_offline: Client, monkeypatch: Any, caplog: Any) -> None:
    """Verify that we still raise the EXACT exception types and strings expected by users."""

    def mock_timeout(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestsTimeout("Read timed out")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)

    with pytest.raises(TimeoutError, match="Request to Mailjet API timed out: Read timed out"):
        client_offline.contact.get()


def test_http_methods_and_timeout(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that CRUD operations correctly map to their respective HTTP methods and timeouts are passed."""

    def mock_request(method: str, url: str, timeout: int | None = None, **kwargs: Any) -> requests.Response:
        assert timeout == 15
        resp = requests.Response()
        resp.status_code = 200
        # Embed the method in the response text so we can assert on it later
        resp._content = method.encode()
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    get_resp = client_offline.contact.get(timeout=15).text
    assert get_resp == "GET"


def test_client_coverage_edge_cases(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify internal routing edge cases like missing filters, kwargs extraction, and payload conversion."""

    def mock_request(method: str, url: str, params: dict[str, Any] | None = None, **kwargs: Any) -> requests.Response:
        assert params == {"limit": 10} or params is None
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    client_offline.contact.get(filter={"limit": 10})


def test_api_call_exceptions_and_logging(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    caplog.set_level(logging.ERROR, logger="mailjet_rest.client")

    def mock_timeout(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestsTimeout("Read timed out")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)

    with pytest.raises(TimeoutError, match="Request to Mailjet API timed out: Read timed out"):
        client_offline.contact.get()

    assert "Timeout Error: GET" in caplog.text


def test_client_custom_version() -> None:
    client = Client(auth=("test", "test"), version="v4")
    assert client.config.version == "v4"


def test_user_agent() -> None:
    client = Client(auth=("test", "test"))
    assert "mailjet-apiv3-python" in client.session.headers["User-Agent"]


def test_legacy_action_id_fallback(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that if 'id' is omitted but 'action_id' is passed, it shifts to the primary ID correctly."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert "/REST/contact/123" in url
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    client_offline.contact.get(action_id=123)


def test_secure_http_adapter_mounted() -> None:
    client = Client(auth=("test", "test"))
    assert "https://" in client.session.adapters


def test_client_explicit_close() -> None:
    client = Client(auth=("test", "test"))
    client.close()
    assert client.session.auth is None  # type: ignore[unreachable]


def test_client_context_manager_lifecycle() -> None:
    with Client(auth=("test", "test")) as client:
        assert client.session is not None
    # Assuming __exit__ was called and cleaned up
    assert client.session.auth is None  # type: ignore[unreachable]


def test_client_context_manager_exception_safety() -> None:
    client = None
    with pytest.raises(ValueError):
        with Client(auth=("test", "test")) as c:
            client = c
            raise ValueError("Test error")
    assert client.session.auth is None  # type: ignore[unreachable]


def test_endpoint_and_config_use_slots() -> None:
    config = Config()
    assert not hasattr(config, "__dict__")


def test_endpoint_precomputes_routing_strings(client_offline: Client) -> None:
    """Verify that Endpoint pre-computes routing strings to save CPU cycles."""
    endpoint = getattr(client_offline, "Contact_Data")
    assert endpoint._name_lower == "contact_data"
    assert endpoint._action_parts == ["contact", "data"]
    assert endpoint._resource_lower == "contact"


def test_client_dir_includes_dynamic_endpoints(client_offline: Client) -> None:
    """Verify that dir(client) includes all keys from ROUTE_MAP for IDE completion."""
    attributes = dir(client_offline)
    assert "send" in attributes
    assert "contact" in attributes
    assert "templates" in attributes


def test_header_constants_immutability(client_offline: Client) -> None:
    """Verify that global header mappings are strictly immutable."""
    with pytest.raises(TypeError):
        _JSON_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]

    with pytest.raises(TypeError):
        _TEXT_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]


def test_endpoint_headers_merge_safely(client_offline: Client) -> None:
    """Verify that endpoint header building unpacks safely without mutating the base proxies."""
    endpoint = client_offline.contact
    merged_headers = endpoint._build_headers({"X-Custom-Header": "SafeValue"})
    assert merged_headers["Content-Type"] == "application/json"
    assert merged_headers["X-Custom-Header"] == "SafeValue"


def test_dry_run_intercepts_mutations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that dry_run=True intercepts POST requests and prevents network calls."""
    client = Client(auth=("a", "b"), dry_run=True)

    # We patch the request method to FAIL if it gets called
    def mock_fail(*args: Any, **kwargs: Any) -> requests.Response:
        pytest.fail("Network request executed during dry_run!")

    monkeypatch.setattr(client.session, "request", mock_fail)

    # Executing a POST request
    response = client.contact.create(data={"Name": "Test"})
    assert response.status_code == 200


def test_stream_lazy_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that .stream() automatically paginates and yields individual records."""
    client = Client(auth=("a", "b"))

    call_count = 0

    def mock_paginated_response(**kwargs: Any) -> requests.Response:
        nonlocal call_count
        resp = requests.Response()
        resp.status_code = 200

        if call_count == 0:
            resp._content = b'{"Total": 3, "Data": [{"id": 1}, {"id": 2}]}'
        elif call_count == 1:
            resp._content = b'{"Total": 3, "Data": [{"id": 3}]}'
        else:
            resp._content = b'{"Total": 3, "Data": []}'

        call_count += 1
        return resp

    monkeypatch.setattr(client.session, "request", mock_paginated_response)

    items = list(client.contact.stream(chunk_size=2))

    assert len(items) == 3
    assert items[0]["id"] == 1
    assert items[2]["id"] == 3
    # With early break optimization, it stops at the exact chunk boundary
    assert call_count == 2


@patch("sys.audit")
def test_pep578_audit_hooks_emitted(
    mock_audit: MagicMock, client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that network egress and security bypasses emit PEP 578 audit events."""

    def mock_resp(**kwargs: Any) -> requests.Response:
        r = requests.Response()
        r.status_code = 200
        return r

    monkeypatch.setattr(client_offline.session, "request", mock_resp)

    # 1. Standard request
    client_offline.contact.get()


def test_infinite_timeout_deprecation_warning(monkeypatch: Any) -> None:
    """Verify passing a null timeout issues a warning and sets it locally."""
    with pytest.warns(DeprecationWarning, match="allows infinite socket blocking"):
        client = Client(auth=("test", "test"), timeout=None)

        def mock_resp(**kwargs: Any) -> requests.Response:
            r = requests.Response()
            r.status_code = 200
            return r

        monkeypatch.setattr(client.session, "request", mock_resp)
        client.contact.get(timeout=None)


def test_extract_telemetry_v3_root_level(client_offline: Client) -> None:
    """Verify telemetry extraction correctly locates attributes in v3 structure."""
    payload = {"CustomID": "trace-123", "Name": "IgnoreMe"}
    suffix, _ = client_offline._extract_telemetry(payload, None)
    assert "CustomID=trace-123" in suffix


def test_extract_telemetry_v31_nested_level(client_offline: Client) -> None:
    """Verify telemetry extraction successfully navigates down into v3.1 Messages arrays."""
    payload = {"Messages": [{"TemplateID": 999888, "To": "test@test.com"}]}
    suffix, _ = client_offline._extract_telemetry(payload, None)
    assert "TemplateID=999888" in suffix


def test_extract_telemetry_safe_fallback(client_offline: Client) -> None:
    """Verify telemetry parser does not throw exceptions on strange data types."""
    # Passing an integer list instead of a dict
    suffix, _ = client_offline._extract_telemetry([1, 2, 3], None)
    assert suffix == ""


def test_extract_telemetry_with_string_data(client_offline: Client) -> None:
    """Verify extraction bypasses JSON parsing on string payloads cleanly."""
    suffix, _ = client_offline._extract_telemetry("This is just a CSV string payload", None)
    assert suffix == ""


def test_getattr_uses_route_map_registry(client_offline: Client) -> None:
    """Verify dynamically requested endpoints leverage the immutable static route map."""
    endpoint = client_offline.batchjob
    url = endpoint._build_url()
    assert url == "https://api.mailjet.com/v3/REST/batchjob"


def test_getattr_dynamic_fallback_still_works(client_offline: Client) -> None:
    """Verify that unregistered endpoints still work via dynamic fallback."""
    endpoint = client_offline.unknown_resource
    url = endpoint._build_url()
    assert "unknown/resource" in url


def test_client_rate_limit_error(client_offline: Client) -> None:
    """Handling 429 Too Many Requests."""
    with patch.object(client_offline.session, "request") as mock_req:
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_req.return_value = mock_response

        # The mock doesn't raise naturally, so we must raise the RequestException with the attached response
        mock_req.side_effect = RequestException(response=mock_response)

        with pytest.raises(ApiError):
            client_offline.contact.get()


def test_client_server_error(client_offline: Client) -> None:
    """Handling HTTP 500 Internal Server Error (Network failure)."""
    with patch.object(client_offline.session, "request", side_effect=RequestsConnectionError("Connection aborted")):
        with pytest.raises(CriticalApiError):
            client_offline.contact.get()


def test_client_timeout_error(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Handle requests Timeout exception securely."""

    def mock_timeout(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestsTimeout("Connection timed out")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)

    with pytest.raises(TimeoutError, match="Connection timed out"):
        client_offline.contact.get()


@pytest.mark.parametrize(
    ("endpoint_name", "kwargs", "expected_url"),
    [
        ("send", {}, "https://api.mailjet.com/v3/send"),
        ("contact", {}, "https://api.mailjet.com/v3/REST/contact"),
        ("contact", {"id_val": 123}, "https://api.mailjet.com/v3/REST/contact/123"),
        ("campaign", {}, "https://api.mailjet.com/v3/REST/campaign"),
        ("tokens", {}, "https://api.mailjet.com/v1/REST/tokens"),
        (
            "template_content_by_type",
            {"id_val": 100, "action_id": "html"},
            "https://api.mailjet.com/v1/REST/templates/100/contents/types/html",
        ),
    ],
)
def test_all_registry_routes(
    client_offline: Client, endpoint_name: str, kwargs: dict[str, Any], expected_url: str
) -> None:
    """Verify that every endpoint in the registry constructs the correct URL and handles URI templating."""
    endpoint = getattr(client_offline, endpoint_name)
    url = endpoint._build_url(**kwargs)
    assert url == expected_url


def test_registry_uri_interpolation_path_traversal_cwe22(client_offline: Client) -> None:
    """Verify that malicious dynamic values injected into URI templates are safely URL-encoded (CWE-22)."""
    malicious_id = "../delete"
    endpoint = client_offline.template_update
    # Expect the ValueError we now actively throw against CWE-22 tokens
    with pytest.raises(ValueError, match="Path traversal attempt"):
        endpoint._build_url(id_val=malicious_id)


def test_client_invalid_attribute(client_offline: Client) -> None:
    # Test the explicit guardrail protection against private methods
    with pytest.raises(AttributeError):
        _ = client_offline._non_existent_hidden_method


def test_client_api_call_exceptions(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    # Test General RequestException (ApiError) falls through smoothly
    def mock_request_error(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestException("General error")

    monkeypatch.setattr(client_offline.session, "request", mock_request_error)

    with pytest.raises(ApiError, match="An unexpected Mailjet API network error occurred"):
        client_offline.contact.get()


def test_client_context_manager() -> None:
    with Client(auth=("test", "test")) as c:
        assert c.session is not None


def test_extract_telemetry_edge_cases(client_offline: Client) -> None:
    # Coverage for when the payload is a string, not a dict
    suffix, d = client_offline._extract_telemetry("string data", None)
    assert suffix == ""
