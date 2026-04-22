"""Unit tests for the Mailjet API client routing, internal logic, and security."""

from __future__ import annotations

import logging
import re
from typing import Any, TYPE_CHECKING

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException
from requests.exceptions import Timeout as RequestsTimeout

from mailjet_rest._version import __version__
from mailjet_rest.client import (
    ApiError,
    Client,
    Config,
    CriticalApiError,
    TimeoutError,
    prepare_url,
)
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.client import _JSON_HEADERS, _TEXT_HEADERS

if TYPE_CHECKING:
    # Explicitly import fixture type for MyPy in a type-checking block
    from _pytest.logging import LogCaptureFixture


@pytest.fixture
def client_offline() -> Client:
    """Return a client with fake credentials for pure offline unit testing."""
    return Client(auth=("fake_public_key", "fake_private_key"), version="v3")


# ==========================================
# 1. Authentication & Initialization Tests
# ==========================================


def test_bearer_token_auth_initialization() -> None:
    """Verify that passing a string to auth configures Bearer token (Content API v1)."""
    token = "secret_v1_token_123"
    client = Client(auth=token)

    assert client.session.auth is None
    assert "Authorization" in client.session.headers
    assert client.session.headers["Authorization"] == f"Bearer {token}"


def test_basic_auth_initialization() -> None:
    """Verify that passing a tuple to auth configures Basic Auth (Email API)."""
    client = Client(auth=("public", "private"))

    assert "Authorization" not in client.session.headers
    assert client.session.auth == ("public", "private")


def test_auth_validation_errors() -> None:
    """Verify that invalid auth formats raise appropriate exceptions to prevent misconfiguration."""
    with pytest.raises(ValueError, match="Basic auth tuple must contain exactly two elements"):
        Client(auth=("public",))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Bearer token cannot be an empty string"):
        Client(auth="   ")

    with pytest.raises(ValueError, match="Bearer token contains invalid characters"):
        Client(auth="token\nwith\nnewline")

    with pytest.raises(TypeError, match="Invalid auth type"):
        Client(auth=["list", "is", "invalid"])  # type: ignore[arg-type]


# ==========================================
# 2. Configuration & Validation Tests
# ==========================================


def test_config_api_url_validation_scheme() -> None:
    """Verify that the SDK refuses to communicate over unencrypted HTTP (CWE-319)."""
    with pytest.raises(ValueError, match="Secure connection required"):
        Config(api_url="http://api.mailjet.com/")


def test_config_api_url_validation_hostname() -> None:
    """Verify that malformed URLs without hostnames are rejected."""
    with pytest.raises(ValueError, match="Invalid api_url: missing hostname"):
        Config(api_url="https:///")


def test_config_timeout_invalid_values() -> None:
    """Verify that extreme timeout values are rejected to prevent resource exhaustion (CWE-400)."""
    with pytest.raises(ValueError, match="Timeout values must be strictly between 1 and 300"):
        Config(timeout=0)

    with pytest.raises(ValueError, match="Timeout values must be strictly between 1 and 300"):
        Config(timeout=500)

    with pytest.raises(ValueError, match="Timeout tuple must contain exactly two elements"):
        Config(timeout=(10,))  # type: ignore[arg-type]


def test_config_timeout_valid_values() -> None:
    """Verify that standard timeout integers and specific (connect, read) tuples are accepted."""
    Config(timeout=15)
    Config(timeout=(5, 30))


def test_url_sanitization_path_traversal() -> None:
    """Verify that injected resource IDs are strictly URL-encoded to prevent Path Traversal (CWE-22)."""
    client = Client(auth=("a", "b"), version="v3")

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        # quote(safe="") converts '/' to '%2F', ensuring directories can't be traversed.
        assert "../delete" not in url
        assert "..%2Fdelete" in url
        resp = requests.Response()
        resp.status_code = 200
        return resp

    client.session.request = mock_request  # type: ignore[assignment]
    # Check that we restored 'id' in public signature
    client.contact.get(id="../delete")


def test_client_repr_and_str_redact_secrets() -> None:
    """Verify that string representations do not leak the private keys (CWE-316)."""
    client = Client(auth=("my_super_secret_public", "my_super_secret_private"))
    rep = repr(client)
    string_rep = str(client)

    assert "my_super_secret" not in rep
    assert "my_super_secret" not in string_rep
    assert "Mailjet Client" in string_rep


def test_client_mount_retry_adapter() -> None:
    """Verify that a Retry adapter is successfully mounted for network resilience."""
    client = Client(auth=("a", "b"))
    adapter = client.session.get_adapter("https://api.mailjet.com/")
    # Replaced blanket type ignore with explicit error codes
    assert adapter.max_retries.total == 3  # type: ignore[attr-defined, union-attr]


def test_ambiguity_warnings_logged(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify that validate_dx_routing correctly flags API version ambiguities via warnings."""

    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 404
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    # Use pytest.warns to explicitly catch the DeprecationWarning instead of relying on loggers
    with pytest.warns(
        DeprecationWarning,
        match=r"Mailjet API Ambiguity: Email API \(v3\) uses singular '/template'",
    ):
        client_offline.templates.get()


# ==========================================
# 3. Dynamic Routing & URL Construction Tests
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
    # Ensure internal _build_url works with restored id
    url = client_offline.templates_contents._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents"


def test_dynamic_versions_content_api_v1_complex_routing(client_offline: Client) -> None:
    """Verify deeply nested Content API routes construct correctly using split action."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_types._build_url(id_val=123, action_id="P")
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/types/P"


@pytest.mark.parametrize(
    "version",
    ["v1", "v3", "v3.1", "v99_future"],
)
def test_dynamic_versions_send_api(version: str, client_offline: Client) -> None:
    """Verify the Send API explicitly bypasses the /REST/ prefix across all versions."""
    client_offline.config.version = version
    url = client_offline.send._build_url()
    assert url == f"https://api.mailjet.com/{version}/send"


def test_build_csv_url_all_branches(client_offline: Client) -> None:
    """Verify the highly specific CSV data upload endpoints construct correctly."""
    client_offline.config.version = "v3"

    url1 = client_offline.contactslist_csvdata._build_url()
    assert url1 == "https://api.mailjet.com/v3/DATA/contactslist"

    url2 = client_offline.contactslist_csvdata._build_url(id_val=456)
    assert url2 == "https://api.mailjet.com/v3/DATA/contactslist/456/CSVData/text:plain"

    url3 = client_offline.contactslist_csverror._build_url(id_val=789)
    assert url3 == "https://api.mailjet.com/v3/DATA/contactslist/789/CSVError/text:csv"

    url4 = client_offline.data_contactslist._build_url(id_val=999)
    assert url4 == "https://api.mailjet.com/v3/data/contactslist/999"


def test_send_api_v3_bad_path_routing(client_offline: Client) -> None:
    """Verify that unexpected operations on the Send API still attempt to route consistently."""
    client_offline.config.version = "v3"
    url = client_offline.send._build_url()
    assert url == "https://api.mailjet.com/v3/send"


def test_content_api_bad_path_routing(client_offline: Client) -> None:
    """Verify that deeply nested paths on the Content API format correctly."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_fakeaction._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/fakeaction"


def test_statcounters_endpoint_routing(client_offline: Client) -> None:
    """Verify statistical routing bypasses standard logic."""
    client_offline.config.version = "v3"
    url = client_offline.statcounters._build_url()
    assert url == "https://api.mailjet.com/v3/REST/statcounters"


# ==========================================
# 4. HTTP Execution & Network Handling Tests
# ==========================================


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
    post_resp = client_offline.contact.create(timeout=15).text
    assert post_resp == "POST"
    # Ensure public 'id' works for update
    update_resp = client_offline.contact.update(id=1, timeout=15).text
    assert update_resp == "PUT"
    delete_resp = client_offline.contact.delete(id=1, timeout=15).text
    assert delete_resp == "DELETE"


def test_client_coverage_edge_cases(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify internal routing edge cases like missing filters, kwargs extraction, and payload conversion."""

    def mock_request(method: str, url: str, params: dict[str, Any] | None = None, **kwargs: Any) -> requests.Response:
        assert params == {"limit": 10} or params is None
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    client_offline.contact.get(filter={"limit": 10})
    client_offline.contact.get(filters={"limit": 10})
    client_offline.contact.get(filter=None)


def test_send_api_v3_1_template_language_variables(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify complex nested payloads (like v3.1 templates) are serialized as JSON correctly."""

    def mock_request(method: str, url: str, data: Any = None, **kwargs: Any) -> requests.Response:
        assert isinstance(data, str)
        assert "TemplateLanguage" in data
        assert "Variables" in data
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    payload = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                "TemplateID": 1234567,
                "TemplateLanguage": True,
                "Variables": {"day": "Tuesday"},
            }
        ]
    }
    client_offline.send.create(data=payload)


def test_api_call_exceptions_and_logging(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    """Verify that raw requests exceptions are caught, logged, and wrapped in SDK-specific exceptions."""
    caplog.set_level(logging.DEBUG, logger="mailjet_rest.client")

    def mock_timeout(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestsTimeout("Read timed out")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)
    with pytest.raises(TimeoutError, match="Request to Mailjet API timed out"):
        client_offline.contact.get()
    assert "Timeout Error: GET" in caplog.text

    def mock_connection_error(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestsConnectionError("Failed to establish a new connection")

    monkeypatch.setattr(client_offline.session, "request", mock_connection_error)
    with pytest.raises(CriticalApiError, match="Connection to Mailjet API failed"):
        client_offline.contact.get()
    assert "Connection Error: Failed to establish" in caplog.text

    def mock_general_exception(*args: Any, **kwargs: Any) -> requests.Response:
        raise RequestException("Generic network failure")

    monkeypatch.setattr(client_offline.session, "request", mock_general_exception)
    with pytest.raises(ApiError, match="An unexpected Mailjet API network error"):
        client_offline.contact.get()
    assert "Request Exception: Generic network failure" in caplog.text

    def mock_400(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 400
        resp._content = b"Bad Request"
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_400)
    client_offline.contact.get()
    # Stringify header to ensure regex match [arg-type] fix
    assert "API Error 400" in caplog.text


def test_client_custom_version() -> None:
    """Verify the SDK allows developers to explicitly request an older API version."""
    client = Client(auth=("a", "b"), version="v3.1")
    assert client.config.version == "v3.1"


def test_user_agent() -> None:
    """Verify the SDK transmits its version correctly to Mailjet servers."""
    client = Client(auth=("a", "b"))
    # Cast header value to string to satisfy MyPy and re.match [arg-type]
    ua_val = str(client.session.headers["User-Agent"])
    assert re.match(r"mailjet-apiv3-python/v\d+\.\d+\.\d+", ua_val)


def test_config_getitem_all_branches() -> None:
    """Verify the dictionary-style access routing logic."""
    config = Config()

    url, headers = config["send"]
    assert url == "https://api.mailjet.com/v3/send"
    assert headers["Content-Type"] == "application/json"

    url, headers = config["contactslist_csvdata"]
    assert url == "https://api.mailjet.com/v3/DATA/contactslist"
    assert headers["Content-Type"] == "text/plain"

    url, headers = config["data_contactslist"]
    assert url == "https://api.mailjet.com/v3/data/contactslist"

    url, headers = config["contact"]
    assert url == "https://api.mailjet.com/v3/REST/contact"


def test_legacy_action_id_fallback(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that if 'id' is omitted but 'action_id' is passed, it shifts to the primary ID correctly."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert "/REST/contact/123" in url
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    # Calling with action_id but no id
    client_offline.contact.get(action_id=123)


def test_prepare_url_headers_and_url() -> None:
    assert prepare_url(re.search(r"[A-Z]", "MyURL")) == "_m"


def test_prepare_url_mixed_case_input() -> None:
    match = re.search(r"[A-Z]", "mixedCaseInput")
    assert match is not None
    assert prepare_url(match) == "_c"


def test_prepare_url_empty_input() -> None:
    match = re.search(r"[A-Z]", "")
    assert match is None


def test_prepare_url_with_numbers_input_bad() -> None:
    match = re.search(r"[A-Z]", "url1With2Numbers")
    assert match is not None
    assert prepare_url(match) == "_w"


def test_prepare_url_leading_trailing_underscores_input_bad() -> None:
    match = re.search(r"[A-Z]", "_urlWithUnderscores_")
    assert match is not None
    assert prepare_url(match) == "_w"


# ==========================================
# 5. Resource Management (Context Managers)
# ==========================================


def test_client_explicit_close(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify the explicit close method correctly calls session.close()."""
    client = Client(auth=("public", "private"))

    close_called = False
    def mock_close() -> None:
        nonlocal close_called
        close_called = True

    monkeypatch.setattr(client.session, "close", mock_close)

    client.close()
    assert close_called is True, "Expected client.session.close() to be called."


def test_client_context_manager_lifecycle(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that the 'with' statement safely cleans up resources on exit."""
    client = Client(auth=("public", "private"))

    close_called = False
    def mock_close() -> None:
        nonlocal close_called
        close_called = True

    monkeypatch.setattr(client.session, "close", mock_close)

    # Act: Use the client within a context manager
    with client as active_client:
        # Assert __enter__ returned the correct object
        assert active_client is client
        # Assert close hasn't been prematurely called
        assert close_called is False

    # Assert __exit__ successfully called the close method
    assert close_called is True, "Context manager __exit__ failed to call close()."


def test_client_context_manager_exception_safety(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that resources are still cleaned up if an exception occurs inside the 'with' block."""
    client = Client(auth=("public", "private"))

    close_called = False
    def mock_close() -> None:
        nonlocal close_called
        close_called = True

    monkeypatch.setattr(client.session, "close", mock_close)

    class SimulatedError(Exception):
        pass

    try:
        with client:
            raise SimulatedError("Something went wrong during an API call")
    except SimulatedError:
        pass

    # The most important assertion: Even though the code crashed, the sockets were closed.
    assert close_called is True, "Exception inside context manager bypassed cleanup!"


# ==========================================
# 6. Performance & Memory Optimization Tests
# ==========================================


def test_endpoint_and_config_use_slots(client_offline: Client) -> None:
    """Verify that __slots__ are strictly enforced for memory optimization.

    This ensures that ephemeral objects do not allocate expensive __dict__
    structures, preserving our 20% CPU/Memory performance gain.
    """
    # Check Config slots
    with pytest.raises(AttributeError):
        client_offline.config.new_dynamic_attr = "test"  # type: ignore[attr-defined]

    # Check Endpoint slots
    endpoint = client_offline.contact
    with pytest.raises(AttributeError):
        endpoint.new_dynamic_attr = "test"  # type: ignore[attr-defined]


def test_endpoint_precomputes_routing_strings(client_offline: Client) -> None:
    """Verify that Endpoint pre-computes routing strings to save CPU cycles."""
    # Using a complex name to test string splitting and lowercasing
    endpoint = getattr(client_offline, "Contact_Data")

    assert getattr(endpoint, "_name_lower") == "contact_data"
    assert getattr(endpoint, "_action_parts") == ["Contact", "Data"]
    assert getattr(endpoint, "_resource_lower") == "contact"


def test_client_retry_strategy_is_shared() -> None:
    """Verify that Retry strategy is a ClassVar, saving instantiation overhead."""
    client1 = Client(auth=("a", "b"))
    client2 = Client(auth=("c", "d"))

    # Assert both clients point to the exact same Retry object in memory
    assert client1._RETRY_STRATEGY is Client._RETRY_STRATEGY
    assert client1._RETRY_STRATEGY is client2._RETRY_STRATEGY
    assert client1._RETRY_STRATEGY.total == 3


def test_security_guard_crlf_rejection_fast_regex() -> None:
    """Verify that the pre-compiled regex efficiently blocks CRLF injections."""
    # Test Carriage Return + Line Feed
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\r\ninjected"})

    # Test Line Feed only
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\n"})

    # Test Carriage Return only
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\r"})

    # Should not raise
    SecurityGuard.validate_crlf_headers({"X-Custom": "safe-value"})

# ==========================================
# 7. Developer Experience (DX) & Constants
# ==========================================

def test_client_dir_includes_dynamic_endpoints(client_offline: Client) -> None:
    """Verify that __dir__ exposes dynamic endpoints for IDE autocompletion."""
    client_dir = dir(client_offline)

    # Check that standard internal attributes are preserved
    assert "session" in client_dir
    assert "config" in client_dir
    assert "api_call" in client_dir

    # Check a representative sample of our injected dynamic endpoints
    expected_dynamic_endpoints = [
        "send",
        "contact",
        "listrecipient",
        "campaigndraft_send",
        "geostatistics",
        "sender_validate"
    ]
    for endpoint in expected_dynamic_endpoints:
        assert endpoint in client_dir, f"Expected endpoint '{endpoint}' missing from __dir__"


def test_header_constants_immutability() -> None:
    """Verify that base headers are MappingProxyType and cannot be mutated."""
    with pytest.raises(TypeError):
        _JSON_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]

    with pytest.raises(TypeError):
        _TEXT_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]


def test_endpoint_headers_merge_safely(client_offline: Client) -> None:
    """Verify that endpoint header building unpacks safely without mutating the base proxies."""
    endpoint = client_offline.contact
    merged_headers = endpoint._build_headers({"X-Custom-Header": "SafeValue"})

    # Check that the merge succeeded
    assert merged_headers["Content-Type"] == "application/json"
    assert merged_headers["X-Custom-Header"] == "SafeValue"

    # Ensure the original proxy wasn't accidentally mutated during the merge
    assert "X-Custom-Header" not in _JSON_HEADERS

    # Check CSV data endpoints fall back to text/plain
    csv_endpoint = getattr(client_offline, "contactslist_csvdata")
    csv_headers = csv_endpoint._build_headers()
    assert csv_headers["Content-Type"] == "text/plain"
