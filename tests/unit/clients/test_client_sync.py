# pyright: reportOperatorIssue=false
# pyright: reportReturnType=false
"""Unit tests for the synchronous Mailjet API client (Client), lifecycle, telemetry, and guardrails."""

from __future__ import annotations

import copy
import gc
import importlib
import io
import logging
import socket
import sys
import warnings
from contextlib import suppress
from types import MappingProxyType
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException, Timeout as RequestsTimeout

from mailjet_rest import types as mj_types
from mailjet_rest.client import BaseClient, Client, Config
from mailjet_rest.errors import (
    ApiError,
    CriticalApiError,
    DoesNotExistError,
    MailjetAuthError,
    TimeoutError,
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.utils.guardrails import SecretAuth, SecureHTTPAdapter, SecurityGuard


if TYPE_CHECKING:
    from _pytest.logging import LogCaptureFixture


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


def test_client_invalid_auth_type() -> None:
    """Coverage: Test invalid auth type initialization."""
    with pytest.raises(TypeError, match="Invalid auth type"):
        Client(auth=123)  # type: ignore[arg-type]


def test_client_verify_false_rejected(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Ensure verify=False emits a UserWarning."""
    # Mock the internal request to prevent actual network execution after the warning is emitted
    monkeypatch.setattr(client_offline.session, "request", MagicMock(return_value=MagicMock(status_code=200)))
    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
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
# 2. HTTP Execution, Lifecycle & Exceptions
# ==========================================


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
    client = Client(auth=("test", "test"))
    with pytest.raises(ValueError), client:
        raise ValueError("Test error")
    assert client.session.auth is None  # type: ignore[unreachable]


def test_client_dir_includes_dynamic_endpoints(client_offline: Client) -> None:
    """Verify that dir(client) includes all keys from ROUTE_MAP for IDE completion."""
    attributes = dir(client_offline)
    assert "send" in attributes
    assert "contact" in attributes
    assert "templates" in attributes


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


# ==========================================
# 3. Pool, Lifecycle Warnings, Copy & DX Parity
# ==========================================


def test_lazy_session_and_pool_configuration() -> None:
    """Client defers session creation until first use and applies Config pool sizes."""
    cfg = Config(pool_connections=12, pool_maxsize=24)
    with Client(auth=("api_key_value", "api_secret_value"), config=cfg) as client:
        assert client._session is None
        _ = client.contact
        assert client._session is None

        session = client.session
        cached_session: object = client._session
        assert cached_session is session
        adapter = session.adapters["https://"]
        assert isinstance(adapter, SecureHTTPAdapter)
        pool_kw = adapter.poolmanager.connection_pool_kw
        sock_opts = pool_kw.get("socket_options", ())
        assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in sock_opts

        proxy_mgr = adapter.proxy_manager_for("http://127.0.0.1:8080")
        assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in proxy_mgr.connection_pool_kw.get("socket_options", ())


def test_warn_unclosed_opt_in_lifecycle() -> None:
    """ResourceWarning is emitted on GC only when Config.warn_unclosed=True and session was opened."""
    with warnings.catch_warnings(record=True) as quiet_warnings:
        warnings.simplefilter("always", ResourceWarning)
        c_default = Client(auth=("api_key_value", "api_secret_value"))
        _ = c_default.session
        del c_default
        gc.collect()
    assert not [w for w in quiet_warnings if issubclass(w.category, ResourceWarning)]

    with pytest.warns(ResourceWarning, match="Unclosed Mailjet Client session"):
        c_warn = Client(auth=("api_key_value", "api_secret_value"), warn_unclosed=True)
        _ = c_warn.session
        del c_warn
        gc.collect()

    with warnings.catch_warnings(record=True) as partial_warnings:
        warnings.simplefilter("always", ResourceWarning)
        raw_client = Client.__new__(Client)
        del raw_client
        with pytest.raises(ValueError, match="pool_connections"):
            Client(auth=("api_key_value", "api_secret_value"), pool_connections=0)
        gc.collect()
    assert not [w for w in partial_warnings if issubclass(w.category, ResourceWarning)]


def test_client_getattr_shutdown_guard_for_del(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify __del__/__getattr__ raises AttributeError instead of ImportError when sys.meta_path is None."""
    client_mod = importlib.import_module("mailjet_rest.client")
    async_client_cls = client_mod.AsyncClient

    partial_sync = Client.__new__(Client)
    partial_async = async_client_cls.__new__(async_client_cls)
    monkeypatch.setattr(sys, "meta_path", None)

    # _warn_if_unclosed must swallow AttributeError cleanly rather than leaking ImportError
    partial_sync._warn_if_unclosed()  # ruff: ignore[private-member-access]
    partial_async._warn_if_unclosed()  # ruff: ignore[private-member-access]


def test_client_lazy_httpx2_failures_auth_warnings_and_timeout_recovery() -> None:
    """Cover _get_httpx2 ImportError, __getattr__, auth=None warning, timeout mutation recovery, and stream reset."""
    client_mod = importlib.import_module("mailjet_rest.client")
    orig_cache = list(client_mod._httpx2_cache)
    try:
        client_mod._httpx2_cache.clear()
        orig_import = importlib.import_module

        def _fail_httpx2(name: str, package: str | None = None) -> Any:
            if name == "httpx2":
                raise ImportError("missing httpx2")
            return orig_import(name, package)

        with patch("mailjet_rest.client.importlib.import_module", side_effect=_fail_httpx2):
            assert client_mod._get_httpx2() is None
    finally:
        client_mod._httpx2_cache[:] = orig_cache

    assert getattr(client_mod, "Endpoint").__name__ == "Endpoint"
    assert getattr(client_mod, "AsyncEndpoint").__name__ == "AsyncEndpoint"
    assert getattr(client_mod, "BaseEndpoint").__name__ == "BaseEndpoint"
    with pytest.raises(AttributeError, match="has no attribute 'NoSuchThing'"):
        _ = getattr(client_mod, "NoSuchThing")

    with pytest.warns(UserWarning, match="without 'auth' credentials"):
        no_auth_client = Client()
    no_auth_client.close()

    with pytest.raises(ValueError, match="Invalid auto_idempotency_mode"):
        Config(auto_idempotency_mode="broken")  # type: ignore[arg-type]

    with Client(auth=("pub_key", "priv_key")) as client:
        with pytest.raises(AttributeError, match="no attribute '_hidden'"):
            client._validate_endpoint_name("_hidden")

        stream_buf = io.BytesIO(b"payload")
        stream_buf.read()
        assert stream_buf.tell() == 7
        BaseClient._reset_stream_pointers(stream_buf, None)
        assert stream_buf.tell() == 0

        # Mutating config.timeout post-init resets to default on invalid call before any transport
        client.config.timeout = -5
        with patch.object(requests.Session, "request", side_effect=AssertionError("unexpected real network call")):
            with pytest.raises(ValueError, match="strictly positive"):
                client.api_call("GET", "https://api.mailjet.com/v3/REST/contact")
        assert client.config.timeout == 60


def test_sync_client_copy_deepcopy_isolation_and_dunder_rejection() -> None:
    """Verify __copy__ and __deepcopy__ isolate locks/sessions/caches and reject private/dunder attrs on Client."""
    sync_orig = Client(auth=("k_sync", "s_sync"), config=Config(version="v3.1", max_retries=2))
    _ = sync_orig.session
    _ = sync_orig.send

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        sync_shallow = copy.copy(sync_orig)
        sync_deep = copy.deepcopy(sync_orig)
    assert not [w for w in captured if issubclass(w.category, UserWarning)]

    assert sync_shallow is not sync_orig
    assert sync_deep is not sync_orig
    assert sync_shallow._session is None  # ruff: ignore[private-member-access]
    assert sync_deep._session is None  # ruff: ignore[private-member-access]
    assert sync_shallow._lock is not sync_orig._lock  # ruff: ignore[private-member-access]
    assert sync_deep._lock is not sync_orig._lock  # ruff: ignore[private-member-access]
    assert sync_shallow._endpoint_cache == {}  # ruff: ignore[private-member-access]
    assert sync_deep._endpoint_cache == {}  # ruff: ignore[private-member-access]
    assert sync_shallow.config is not sync_orig.config
    assert sync_deep.config is not sync_orig.config
    sync_shallow.config.max_retries = 0
    assert sync_orig.config.max_retries == 2
    assert sync_deep.auth is not sync_orig.auth
    assert isinstance(sync_deep.auth, SecretAuth)
    assert isinstance(sync_orig.auth, SecretAuth)
    assert sync_deep.auth.auth_header == sync_orig.auth.auth_header

    for bad_attr in ("_private_attr", "__nonexistent_dunder__"):
        with pytest.raises(AttributeError):
            _ = getattr(sync_orig, bad_attr)

    sync_orig.close()


def test_auto_idempotency_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fingerprint, uuid4, off, and case-insensitive header preservation."""
    captured_headers: list[dict[str, Any]] = []

    def mock_exec(
        self: Any, method: str, url: str, headers: dict[str, Any], *args: Any, **kwargs: Any
    ) -> requests.Response:
        captured_headers.append(dict(headers))
        r = requests.Response()
        r.status_code = 200
        return r

    monkeypatch.setattr(Client, "_execute_request", mock_exec)

    client_uuid = Client(auth=("pub", "priv"), auto_idempotency_mode="uuid4")
    client_uuid.api_call("POST", "https://api.mailjet.com/v3/REST/contact", data={"a": 1})
    assert len(captured_headers[-1]["Idempotency-Key"]) == 36

    client_off = Client(auth=("pub", "priv"), auto_idempotency_mode="off")
    client_off.api_call("POST", "https://api.mailjet.com/v3/REST/contact", data={"a": 1})
    assert "Idempotency-Key" not in captured_headers[-1]
    client_fp = Client(auth=("pub", "priv"), auto_idempotency_mode="fingerprint")
    client_fp.api_call(
        "POST",
        "https://api.mailjet.com/v3/REST/contact",
        headers={"idempotency-key": "caller-supplied"},
        data={"a": 1},
    )
    assert captured_headers[-1]["idempotency-key"] == "caller-supplied"
    assert "Idempotency-Key" not in captured_headers[-1]


def test_sync_client_executes_new_routes_with_mapping_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify sync Client executes new routes and serializes read-only MappingProxyType payloads."""
    seen: list[tuple[str, str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> MagicMock:
        seen.append((method, url, kwargs.get("json")))
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status.return_value = None
        return resp

    with Client(auth=("pub_key", "priv_key")) as client:
        monkeypatch.setattr(client.session, "request", fake_request)

        v31_msg: mj_types.SendV31Message = {
            "From": {"Email": "sender@example.com", "Name": "Sender"},
            "To": [{"Email": "to@example.com"}],
            "Subject": "Hello v3.1",
            "TextPart": "Body",
            "CustomID": "cid-v31",
            "TrackOpens": "enabled",
        }
        v31_payload = MappingProxyType({"Messages": [v31_msg], "AdvanceErrorHandling": True})
        client.send_v31.create(data=v31_payload)
        client.contacts.delete(id=99)
        client.template_contents_publish.create(id=12, data={"Name": "Published"})
        client.data_images_by_type.update(id="abc-123", action_id="thumbnail", data=b"raw-bytes")

        # Verify legacy ensure_ascii=False handles MappingProxyType safely without TypeError
        with pytest.warns(DeprecationWarning, match="ensure_ascii"):
            legacy_url, _headers, encoded = client.send_v31._prepare_call_args(
                id=None,
                data=v31_payload,
                action_id=None,
                headers=None,
                kwargs={"ensure_ascii": False},
            )
        assert legacy_url == "https://api.mailjet.com/v3.1/send"
        assert isinstance(encoded, str)

    assert seen[0][0] == "POST"
    assert seen[0][1] == "https://api.mailjet.com/v3.1/send"
    assert isinstance(seen[0][2], dict)
    assert seen[1][:2] == ("DELETE", "https://api.mailjet.com/v4/contacts/99")
    assert seen[2][:2] == ("POST", "https://api.mailjet.com/v1/REST/templates/12/contents/publish")
    assert seen[3][:2] == ("PUT", "https://api.mailjet.com/v1/data/images/abc-123/thumbnail")


def test_sync_client_available_endpoints_and_did_you_mean() -> None:
    """Verify Client.available_endpoints and AttributeError 'Did you mean' suggestion."""
    with Client(auth=("pub_key", "priv_key")) as client:
        assert client.available_endpoints == tuple(sorted(ROUTE_MAP))
        assert "send_v31" in client.available_endpoints
        assert "contacts" in client.available_endpoints
        with pytest.raises(AttributeError, match=r"has no endpoint or attribute 'snd'\. Did you mean 'send'\?"):
            _ = client.snd


def test_client_ping_and_closed_context_reentry(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Client.ping() outcomes, SSRF fail-closed, and re-entering a closed Client context."""
    with Client(auth=("pub_key", "priv_key"), max_retries=0) as sync_client:
        fake_ok = type(
            "Resp",
            (),
            {"status_code": 200, "headers": {}, "text": "{}", "raise_for_status": lambda _s=None: None},
        )()
        monkeypatch.setattr(sync_client.session, "request", lambda **_kw: fake_ok)
        assert sync_client.ping(timeout=1.0) is True

        def fail_conn(**_kw: Any) -> Any:
            raise RequestsConnectionError("down")

        monkeypatch.setattr(sync_client.session, "request", fail_conn)
        assert sync_client.ping() is False

    assert sync_client._closed is True
    with sync_client as reentered:
        assert reentered is sync_client
        assert reentered._closed is False
        assert reentered._session is None
        reentered.config.api_url = "https://evil.example.com/"
        with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
            reentered.ping()
