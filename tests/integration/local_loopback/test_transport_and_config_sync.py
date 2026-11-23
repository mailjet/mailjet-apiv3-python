"""Offline loopback TLS 1.2+ and HTTP integration tests for sync Client, Endpoint, Config, errors, retry, and routing."""

from __future__ import annotations

import copy
import importlib
import io
import ssl
import types
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from typing import Any, cast

import pytest

from mailjet_rest import (
    ActionDeniedError,
    ApiError,
    ApiRateLimitError,
    AuthorizationError,
    Client,
    Config,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    MailjetNetworkError,
    TimeoutError as MailjetTimeoutError,
    ValidationError,
)
from mailjet_rest.client import BaseClient, _httpx2, _resolve_proxy_url, logging_handler, parse_response
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.errors import (
    MAX_ERROR_BODY_CHARS,
    extract_error_detail,
    handle_api_error,
    raise_mapped_http_error,
    sanitize_error_text,
)
from mailjet_rest.utils import version as version_mod
from mailjet_rest.utils.retry import (
    JitterRetry,
    compute_retry_delay,
    parse_retry_after_http_date,
    reset_stream_pointers,
    snapshot_stream_offsets,
)
from mailjet_rest.utils.routing import (
    build_endpoint_headers,
    build_endpoint_url,
    cast_query_param,
    external_stacklevel,
    normalize_stream_filters,
    parse_stream_page,
    resolve_dynamic_route,
    validate_stream_args,
)
from mailjet_rest.utils.transport_security import (
    SecretAuth,
    SecureHTTPAdapter,
    build_httpx2_transport,
    build_ssl_context_with_cert,
    coerce_httpx2_timeout,
    get_secure_ssl_context,
    resolve_tls_verify,
)
from tests.integration.local_loopback._servers import (
    _BytesPathLike,
    _RecordingHTTPSServer,
    unused_loopback_port,
)


def test_lazy_package_exports_and_version_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise mailjet_rest.__init__ lazy exports, client module __getattr__, and version.py helpers."""
    mailjet_rest = importlib.import_module("mailjet_rest")
    client_mod = importlib.import_module("mailjet_rest.client")
    assert mailjet_rest.__getattr__("__version__") == mailjet_rest.__version__
    assert mailjet_rest.__getattr__("Endpoint") is Endpoint
    assert mailjet_rest.__getattr__("AsyncEndpoint") is client_mod.AsyncEndpoint
    assert mailjet_rest.__getattr__("ActionDeniedError") is ActionDeniedError
    assert mailjet_rest.__getattr__("MockMailjetClient").__name__ == "MockMailjetClient"
    assert mailjet_rest.__getattr__("get_version") is version_mod.get_version
    assert callable(mailjet_rest.__getattr__("verify_webhook_signature"))

    # Verify allowlisted submodule dispatcher directly as well as rejection of unknown entries
    assert mailjet_rest._import_known_submodule("mailjet_rest.client") is client_mod
    assert mailjet_rest._import_known_submodule("mailjet_rest.endpoint").Endpoint is Endpoint
    assert mailjet_rest._import_known_submodule("mailjet_rest.errors").ApiError is ApiError
    assert mailjet_rest._import_known_submodule("mailjet_rest.testing").MockMailjetClient is not None
    assert mailjet_rest._import_known_submodule("mailjet_rest.utils.version") is version_mod
    assert callable(mailjet_rest._import_known_submodule("mailjet_rest.webhooks").verify_webhook_signature)
    with pytest.raises(ImportError, match="Disallowed lazy submodule"):
        mailjet_rest._import_known_submodule("invalid.mod")

    with pytest.raises(AttributeError, match="no attribute"):
        mailjet_rest.__getattr__("nonexistent_export_xyz")

    exported = dir(mailjet_rest)
    assert "__version__" in exported
    assert "Client" in exported

    # mailjet_rest.client lazy __getattr__
    assert client_mod.Endpoint is Endpoint
    assert client_mod.AsyncEndpoint.__name__ == "AsyncEndpoint"
    assert client_mod.BaseEndpoint.__name__ == "BaseEndpoint"
    with pytest.raises(AttributeError, match="no attribute"):
        getattr(client_mod, "nonexistent_client_attr_xyz")

    monkeypatch.setattr(client_mod, "_httpx2", None, raising=False)
    with pytest.raises(ImportError, match="httpx2"):
        client_mod.AsyncClient(auth="tok")
    monkeypatch.undo()

    # mailjet_rest.utils.version helpers
    assert version_mod.parse_semver_triplet("1.10.0") == (1, 10, 0)
    assert version_mod.parse_semver_triplet(" 1.10.0rc1 ") == (1, 10, 0)
    for bad_ver in ("1.2", "a.2.3", "1.b.3", "1.2.abc"):
        with pytest.raises(ValueError):
            version_mod.parse_semver_triplet(bad_ver)

    assert version_mod.clean_version("2.5.9.post1") == (2, 5, 9)
    assert version_mod.clean_version("invalid") == (0, 0, 0)
    assert version_mod.clean_version(cast("Any", None)) == (0, 0, 0)

    assert version_mod.get_version() == version_mod.get_version(version_mod.VERSION)
    assert version_mod.get_version((1, 2, 3)) == "1.2.3"
    with pytest.raises(ValueError, match="3 items"):
        version_mod.get_version((1, 2))
    with pytest.raises(ValueError, match="3 items"):
        version_mod.get_version((1, 2, 3, 4))


def test_config_validation_and_customization(loopback_servers: dict[str, Any]) -> None:
    """Exercise Config normalization, defaults, and all validation failure paths."""
    ca_path: Path = loopback_servers["ca_path"]
    no_slash = loopback_servers["https_url"].rstrip("/")
    cfg = Config(
        version="v3.1",
        api_url=no_slash,
        user_agent="custom-sdk/2.0",
        timeout=(2.0, 5.0),
        dry_run=True,
        enable_security_audit=True,
        verify=ca_path,
        auto_idempotency_mode="uuid4",
        pool_connections=10,
        pool_maxsize=20,
        warn_unclosed=True,
        max_retries=5,
        trust_env=True,
    )
    assert cfg.api_url == f"{no_slash}/"
    assert cfg.verify == str(ca_path)
    assert cfg.version == "v3.1"
    assert cfg.user_agent == "custom-sdk/2.0"
    assert cfg.dry_run is True

    with pytest.warns(DeprecationWarning, match="infinite socket blocking"):
        none_timeout_cfg = Config(timeout=None)
    assert none_timeout_cfg.timeout is None

    for bad_url in (
        "https://localhost/v3?foo=bar",
        "https://localhost/v3#frag",
        "ftp://localhost/",
        "https://user:pass@localhost/",  # pragma: allowlist secret
        "https://evil.example/",
    ):
        with pytest.raises(ValueError):
            Config(api_url=bad_url)

    for bad_timeout in (-1, 0, True):
        with pytest.raises((ValueError, TypeError)):
            Config(timeout=cast("Any", bad_timeout))

    for bad_retries in (-1, True, Config.MAX_RETRIES_LIMIT + 1):
        with pytest.raises(ValueError):
            Config(max_retries=cast("Any", bad_retries))

    with pytest.raises(ValueError):
        Config(pool_connections=0)
    with pytest.raises(ValueError):
        Config(pool_maxsize=0)

    with pytest.raises(TypeError, match="trust_env must be a bool"):
        Config(trust_env=cast("Any", "true"))
    with pytest.raises(TypeError, match="warn_unclosed must be a bool"):
        Config(warn_unclosed=cast("Any", 1))
    with pytest.raises(ValueError, match="Invalid auto_idempotency_mode"):
        Config(auto_idempotency_mode=cast("Any", "bogus"))


def test_transport_security_tls_verify_certs_and_secret_auth(
    loopback_servers: dict[str, Any],
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise transport_security.py TLS validation, SSL context builders, adapter, SecretAuth, and proxy parser."""
    ca_path: Path = loopback_servers["ca_path"]
    key_path: Path = loopback_servers["key_path"]
    combined_pem: Path = loopback_servers["combined_pem"]

    # resolve_tls_verify paths
    assert resolve_tls_verify(True) is True
    assert resolve_tls_verify(ca_path) == str(ca_path)
    with pytest.raises(ValueError, match="cannot be disabled"):
        resolve_tls_verify(False)
    with pytest.raises(ValueError, match="cannot be disabled"):
        resolve_tls_verify(None)

    with pytest.raises(TypeError, match="Invalid CA bundle path type"):
        resolve_tls_verify(_BytesPathLike())
    with pytest.raises(ValueError, match="without control characters"):
        resolve_tls_verify("   ")
    with pytest.raises(ValueError, match="without control characters"):
        resolve_tls_verify("bad\x00.pem")
    with pytest.raises(ValueError, match="does not exist or is not a file"):
        resolve_tls_verify(tmp_path / "missing.pem")
    with pytest.raises(ValueError, match="does not exist or is not a file"):
        resolve_tls_verify(tmp_path)
    with pytest.raises(TypeError, match="Invalid 'verify' type"):
        resolve_tls_verify(12345)

    def _raise_runtime_error(_self: Path) -> Path:
        raise RuntimeError("no home")

    monkeypatch.setattr(Path, "expanduser", _raise_runtime_error)
    with pytest.raises(ValueError, match="could not determine home directory"):
        resolve_tls_verify("~/ca.pem")
    monkeypatch.undo()

    # SSLContext builders
    default_ctx = get_secure_ssl_context(None)
    assert default_ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    assert build_ssl_context_with_cert(str(ca_path), None) is get_secure_ssl_context(str(ca_path))

    pair_ctx = build_ssl_context_with_cert(str(ca_path), (str(cert_path := ca_path), str(key_path)))
    assert pair_ctx.minimum_version == ssl.TLSVersion.TLSv1_2
    single_ctx = build_ssl_context_with_cert(str(ca_path), combined_pem)
    assert single_ctx.minimum_version == ssl.TLSVersion.TLSv1_2

    with pytest.raises(ValueError, match="must contain"):
        build_ssl_context_with_cert(str(ca_path), cast("Any", (str(cert_path),)))
    with pytest.raises(TypeError, match="Invalid 'cert' type"):
        build_ssl_context_with_cert(str(ca_path), cast("Any", 999))

    # SecureHTTPAdapter helpers & proxy manager & cert_verify branches
    adapter = SecureHTTPAdapter(ca_bundle=str(ca_path))
    assert SecureHTTPAdapter._get_secure_ssl_context(str(ca_path)).minimum_version == ssl.TLSVersion.TLSv1_2
    pm = adapter.proxy_manager_for("http://127.0.0.1:8888")
    assert pm is not None

    class _DummyConn:
        ssl_context: Any = None
        ca_certs: Any = "old"
        ca_cert_dir: Any = "old_dir"
        cert_reqs: Any = None
        assert_hostname: Any = None
        cert_file: Any = None
        key_file: Any = None

    http_conn = _DummyConn()
    adapter.cert_verify(http_conn, "http://127.0.0.1/v3/REST/contact", True, None)
    assert http_conn.ssl_context is None

    iso_conn = _DummyConn()
    adapter.cert_verify(iso_conn, "https://127.0.0.1/v3/REST/contact", True, None)
    assert iso_conn.ssl_context is not adapter._ssl_context
    assert iso_conn.ca_certs is None

    if _httpx2 is not None:
        t_tuple = coerce_httpx2_timeout(_httpx2, (1.5, 4.5))
        assert t_tuple.connect == 1.5
        assert t_tuple.read == 4.5
        assert coerce_httpx2_timeout(_httpx2, None) is None
        transport = build_httpx2_transport(_httpx2, str(ca_path), pool_connections=2, pool_maxsize=4, cert=combined_pem)
        assert transport is not None

    # SecretAuth validation, constant-time equality, indexing/iter protection, redaction
    with pytest.raises(ValueError, match="2-tuple"):
        SecretAuth(("only_one",))
    with pytest.raises(TypeError, match="must be strings"):
        SecretAuth((123, "secret"))
    with pytest.raises(ValueError, match="control characters"):
        SecretAuth(("key\r\n", "secret"))
    with pytest.raises(ValueError, match="Latin-1"):
        SecretAuth(("k€y", "secret"))

    sa = SecretAuth(("pub", "priv"))
    assert sa.auth_header.startswith("Basic ")
    assert hash(sa) == hash(SecretAuth(("pub", "priv")))
    assert sa == SecretAuth(("pub", "priv"))
    assert sa != SecretAuth(("pub", "other"))
    assert sa == ("pub", "priv")
    assert sa != ("pub", "wrong")
    assert sa != "not-a-tuple"
    assert sa != ("\ud800", "priv")
    assert repr(sa) == "SecretAuth(***REDACTED***)"
    assert str(sa) == "SecretAuth(***REDACTED***)"
    with pytest.raises(TypeError, match="indexing is blocked"):
        _ = sa[0]
    with pytest.raises(TypeError, match="iteration is blocked"):
        iter(sa)

    # _resolve_proxy_url
    assert _resolve_proxy_url(None) is None
    assert _resolve_proxy_url("https://proxy.local:8443") == "https://proxy.local:8443"
    assert _resolve_proxy_url({"HTTPS": "https://p1:8443", "http": "http://p2:8080"}) == "https://p1:8443"
    assert _resolve_proxy_url({"all://": "https://p3:8443"}) == "https://p3:8443"
    assert _resolve_proxy_url({"http": "http://p4:8080"}) == "http://p4:8080"
    assert _resolve_proxy_url({}) is None
    assert _resolve_proxy_url(123) is None
    with pytest.raises(ValueError, match="Unsupported proxy mapping keys"):
        _resolve_proxy_url({"ftp": "ftp://bad:21"})


def test_errors_mapping_sanitization_and_real_socket_errors(loopback_servers: dict[str, Any]) -> None:
    """Exercise errors.py formatting, bounds truncation, edge fallbacks, and real-socket HTTP status mapping."""
    assert sanitize_error_text("line1\r\n\x00\t" + "x" * 50, max_chars=12).endswith("...[truncated]")
    assert "\n" not in sanitize_error_text("a\nb\x7fc", max_chars=100)

    class _StubResp:
        def __init__(self, status_code: int, text: str, json_val: Any = None, *, bad_json: bool = False) -> None:
            self.status_code = status_code
            self.text = text
            self._json_val = json_val
            self._bad_json = bad_json

        def json(self) -> Any:
            if self._bad_json:
                raise ValueError("bad json")
            return self._json_val

    assert extract_error_detail(_StubResp(400, "", ["arr"]), "") == ""
    assert extract_error_detail(_StubResp(400, "plain", ["arr"]), "plain") == ": plain"
    assert extract_error_detail(
        _StubResp(400, "", {"Messages": [{"Errors": [{"ErrorMessage": "bad email"}]}]}), ""
    ) == (": bad email")
    assert extract_error_detail(_StubResp(400, "fallback", {"Messages": "not-list"}), "fallback") == ": fallback"
    assert extract_error_detail(_StubResp(400, "fallback2", {"Messages": [{"Errors": ["not-dict"]}]}), "fallback2") == (
        ": fallback2"
    )

    with pytest.raises(ApiError, match="unexpected Mailjet API network error"):
        raise_mapped_http_error(_StubResp(200, "ok"), RuntimeError("weird"))
    with pytest.raises(ApiError, match="unexpected Mailjet API network error"):
        handle_api_error(RuntimeError("no response"))

    assert isinstance(AuthorizationError("auth", 401), MailjetAuthError)
    assert isinstance(ActionDeniedError("denied", 403), MailjetAuthError)

    url: str = loopback_servers["https_url"]
    ca_path: Path = loopback_servers["ca_path"]

    with Client(auth=("pub", "priv"), api_url=url, verify=ca_path, max_retries=0) as c:
        with pytest.raises(MailjetAuthError) as auth_exc:
            c.forbidden.get()
        assert auth_exc.value.status_code == 403
        assert "Forbidden action" in str(auth_exc.value)

        with pytest.raises(DoesNotExistError) as not_found_exc:
            c.notfound.get()
        assert not_found_exc.value.status_code == 404

        with pytest.raises(ApiRateLimitError) as rate_exc:
            c.always429.get()
        assert rate_exc.value.status_code == 429

        with pytest.raises(MailjetApiError) as err500_exc:
            c.err500.get()
        assert err500_exc.value.status_code == 500

        with pytest.raises(ValidationError) as list_exc:
            c.badreqlist.get()
        assert "list-level-error" in str(list_exc.value)

        with pytest.raises(ValidationError) as empty_exc:
            c.badreqempty.get()
        assert empty_exc.value.response_body == ""

        with pytest.raises(ValidationError) as big_exc:
            c.badreqbig.get()
        assert big_exc.value.response_body.endswith("...[truncated]")
        assert len(big_exc.value.response_body) < MAX_ERROR_BODY_CHARS + 50

        with pytest.raises(ValidationError) as info_exc:
            c.badreqinfo.get()
        assert "Schema mismatch" in info_exc.value.response_body

        # With JitterRetry(total=0), urllib3 wraps ReadTimeoutError in MaxRetryError -> RequestsConnectionError -> CriticalApiError
        with pytest.raises(CriticalApiError):
            c.slow.get(timeout=0.05)

        # With read=False / total=False, urllib3 re-raises ReadTimeoutError directly -> requests.ReadTimeout -> MailjetTimeoutError
        c.session.get_adapter("https://").max_retries = JitterRetry(total=False, read=False)  # type: ignore[arg-type]
        with pytest.raises(MailjetTimeoutError) as to_exc:
            c.slow.get(timeout=0.05)
        assert isinstance(to_exc.value, MailjetNetworkError)
        assert isinstance(to_exc.value, TimeoutError)

    dead_url = f"https://127.0.0.1:{unused_loopback_port()}/"
    with Client(auth=("pub", "priv"), api_url=dead_url, verify=ca_path, max_retries=0) as dead_c:
        with pytest.raises(CriticalApiError) as conn_exc:
            dead_c.contact.get()
        assert isinstance(conn_exc.value, MailjetNetworkError)


def test_retry_helpers_http_date_and_stream_offsets() -> None:
    """Exercise sync retry.py JitterRetry, HTTP-date parsing, and stream pointer snapshots/rewinds."""
    # JitterRetry backoff calculation for empty vs populated history
    jr = JitterRetry(total=3, backoff_factor=1)
    assert jr.get_backoff_time() == 0
    jr_after_one = jr.increment(method="GET", url="https://127.0.0.1/v3/REST/contact")
    jr_after_two = jr_after_one.increment(method="GET", url="https://127.0.0.1/v3/REST/contact")
    assert 0.0 <= jr_after_two.get_backoff_time() <= 2.0

    # parse_retry_after_http_date
    future_hdr = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=5), usegmt=True)
    parsed_future = parse_retry_after_http_date(future_hdr, max_delay=60.0)
    assert parsed_future is not None and 0.0 < parsed_future <= 6.0

    far_future_hdr = format_datetime(datetime.now(timezone.utc) + timedelta(seconds=300), usegmt=True)
    assert parse_retry_after_http_date(far_future_hdr, max_delay=10.0) == 10.0

    # Naive HTTP-date (tzinfo is None) in the past -> clamped to 0.0
    assert parse_retry_after_http_date("Fri, 01 Jan 2021 00:00:00", max_delay=60.0) == 0.0
    assert parse_retry_after_http_date("not-a-valid-http-date") is None

    # compute_retry_delay branches
    assert compute_retry_delay(0, "   ", max_delay=5.0) <= 5.0
    assert compute_retry_delay(0, "3", max_delay=10.0) == 3.0
    assert compute_retry_delay(0, "-2", max_delay=5.0) <= 5.0
    assert compute_retry_delay(0, "nan", max_delay=5.0) <= 5.0
    assert compute_retry_delay(0, future_hdr, max_delay=60.0) > 0.0
    assert compute_retry_delay(0, "invalid-date", max_delay=5.0) <= 5.0

    # Stream offset snapshot & rewind helpers
    b1 = io.BytesIO(b"abcdef")
    b1.seek(2)
    b2 = io.BytesIO(b"12345")
    b2.seek(1)
    b_closed = io.BytesIO(b"closed")
    b_closed.close()

    class _NoSeekableAttr:
        def __init__(self) -> None:
            self.pos = 3

        def seek(self, pos: int) -> None:
            self.pos = pos

        def tell(self) -> int:
            return self.pos

    class _Unseekable:
        def seekable(self) -> bool:
            return False

        def seek(self, pos: int) -> None:
            raise OSError("unseekable")

    class _BrokenTellSeek:
        def tell(self) -> int:
            raise OSError("no tell")

        def seek(self, _pos: int) -> None:
            raise ValueError("bad seek")

    class _NoTell:
        def seek(self, _pos: int) -> None:
            pass

    class _BoolTell:
        def tell(self) -> bool:
            return True

        def seek(self, _pos: int) -> None:
            pass

    no_seekable = _NoSeekableAttr()
    deep_stream = io.BytesIO(b"too-deep")
    payload = [b1, {"nested": {"a": {"b": {"c": {"d": deep_stream}}}}}]
    files = {
        "f1": b2,
        "f2": b_closed,
        "f3": _Unseekable(),
        "f4": no_seekable,
        "f5": _BrokenTellSeek(),
        "f6": _NoTell(),
        "f7": _BoolTell(),
    }

    offsets = snapshot_stream_offsets(payload, files)
    assert offsets[id(b1)] == 2
    assert offsets[id(b2)] == 1
    assert offsets[id(no_seekable)] == 3
    assert id(deep_stream) not in offsets

    b1.read()
    b2.read()
    no_seekable.pos = 99
    reset_stream_pointers(payload, files, offsets)
    assert b1.tell() == 2
    assert b2.tell() == 1
    assert no_seekable.pos == 3

    reset_stream_pointers(b1, None, None)
    assert b1.tell() == 0


def test_routing_urls_headers_query_casting_and_stream_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise routing.py registry/dynamic/CSV/data URL resolution, headers, query casting, and stream validation."""
    # external_stacklevel fallback paths
    assert external_stacklevel("nonexistent_package_root") >= 1

    def _raise_val_err(_depth: int) -> Any:
        raise ValueError("no frame")

    monkeypatch.setattr("sys._getframe", _raise_val_err)
    assert external_stacklevel() == 2
    monkeypatch.undo()

    # Dynamic route resolution variants
    assert resolve_dynamic_route("send", "send", ["send"], "https://127.0.0.1", "v3", None, None)[0] == (
        "https://127.0.0.1/v3/send"
    )
    assert build_endpoint_url(
        "customjob_csvdata",
        "customjob_csvdata",
        "customjob",
        ["customjob", "csvdata"],
        "https://127.0.0.1/",
        "v3",
        id_val=12,
        action_id="part",
    ) == ("https://127.0.0.1/v3/DATA/customjob/12/CSVData/text:plain/part")
    assert build_endpoint_url(
        "customjob_csverror", "customjob_csverror", "customjob", ["customjob", "csverror"], "https://127.0.0.1/", "v3"
    ) == ("https://127.0.0.1/v3/DATA/customjob")
    assert build_endpoint_url(
        "data_custom_assets",
        "data_custom_assets",
        "data",
        ["data", "custom", "assets"],
        "https://127.0.0.1/",
        "v1",
        id_val=5,
        action_id="raw",
    ) == ("https://127.0.0.1/v1/data/custom/assets/5/raw")
    assert build_endpoint_url(
        "contact_customAction",
        "contact_customaction",
        "contact",
        ["contact", "custom-action"],
        "https://127.0.0.1/",
        "v3",
    ) == ("https://127.0.0.1/v3/REST/contact/custom-action")
    assert build_endpoint_url(
        "contact_customAction",
        "contact_customaction",
        "contact",
        ["contact", "custom-action"],
        "https://127.0.0.1/",
        "v3",
        id_val=10,
        action_id="sub",
    ) == ("https://127.0.0.1/v3/REST/contact/10/custom-action/sub")
    assert build_endpoint_url(
        "contact_customAction",
        "contact_customaction",
        "contact",
        ["contact", "custom-action"],
        "https://127.0.0.1/",
        "v3",
        id_val=10,
    ) == ("https://127.0.0.1/v3/REST/contact/10/custom-action")
    assert build_endpoint_url(
        "contact", "contact", "contact", ["contact"], "https://127.0.0.1/", "v3", id_val=1, action_id="manage"
    ) == ("https://127.0.0.1/v3/REST/contact/1/manage")

    # Headers
    assert build_endpoint_headers("contactslist_csvdata")["Content-Type"] == "text/plain"
    assert build_endpoint_headers("batchjob_csverror")["Content-Type"] == "text/csv"
    assert build_endpoint_headers("contact", {"X-Trace": "t1"}) == {"Content-Type": "application/json", "X-Trace": "t1"}
    assert build_endpoint_headers("contact", {"content-type": "application/vnd.api+json"}) == {
        "content-type": "application/vnd.api+json"
    }

    # cast_query_param all types + empty + bool/numeric TypeError
    assert cast_query_param(True, "YES") is True
    assert cast_query_param(True, "0") is False
    assert cast_query_param(True, []) is False
    assert cast_query_param(0, "42") == 42
    assert cast_query_param(0, []) == 0
    assert cast_query_param(0.0, "3.14") == 3.14
    assert cast_query_param(0.0, []) == 0.0
    assert cast_query_param([], ("a", "b")) == ["a", "b"]
    assert cast_query_param([], ()) == []
    assert cast_query_param((), ["a", "b"]) == ("a", "b")
    assert cast_query_param((), []) == ()
    assert cast_query_param(set(), ["a", "a"]) == {"a"}
    assert cast_query_param(set(), []) == set()
    assert cast_query_param("s", "hello") == "hello"
    assert cast_query_param("s", ["a", "b"]) == ["a", "b"]
    assert cast_query_param("s", []) == ""
    with pytest.raises(TypeError, match="Boolean value"):
        cast_query_param(0, True)
    with pytest.raises(TypeError, match="Boolean value"):
        cast_query_param(0.0, False)

    # normalize_stream_filters & validate_stream_args
    norm_f, off = normalize_stream_filters({"offset": "4", "limit": 99}, 50)
    assert off == 4
    assert norm_f == {"Limit": 50}

    with pytest.raises(ValueError, match="Offset filter must be an integer"):
        normalize_stream_filters({"Offset": "abc"}, 10)
    with pytest.raises(ValueError, match="non-negative integer"):
        normalize_stream_filters({"offset": -1}, 10)

    validate_stream_args("GET", 10, None)
    with pytest.raises(ValueError, match="GET requests only"):
        validate_stream_args("POST", 10, 5)
    with pytest.raises(ValueError, match="strictly positive"):
        validate_stream_args("GET", 0, None)
    with pytest.raises(ValueError, match="strictly positive"):
        validate_stream_args("GET", cast("Any", True), None)
    with pytest.raises(ValueError, match="exceeds Mailjet's maximum"):
        validate_stream_args("GET", 1001, None)
    with pytest.raises(ValueError, match="non-negative"):
        validate_stream_args("GET", 10, -1)

    # parse_stream_page edge cases
    class _PageResp:
        def __init__(self, body: Any, *, bad_json: bool = False) -> None:
            self.status_code = 200
            self.text = "raw"
            self._body = body
            self._bad = bad_json

        def json(self) -> Any:
            if self._bad:
                raise ValueError("bad")
            return self._body

    assert parse_stream_page(_PageResp({"Count": 0})) == []
    with pytest.raises(MailjetApiError, match="Malformed JSON"):
        parse_stream_page(_PageResp(None, bad_json=True))
    with pytest.raises(MailjetApiError, match="Expected JSON object"):
        parse_stream_page(_PageResp([1, 2]))
    with pytest.raises(MailjetApiError, match="Expected 'Data' list"):
        parse_stream_page(_PageResp({"Data": "oops"}))


def test_sync_client_and_endpoint_real_https_and_http_integration(
    loopback_servers: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise sync Client and Endpoint over real loopback TLS 1.2+ and HTTP sockets."""
    https_url: str = loopback_servers["https_url"]
    http_url: str = loopback_servers["http_url"]
    ca_path: Path = loopback_servers["ca_path"]
    untrusted_ca: Path = loopback_servers["untrusted_ca"]
    https_srv: _RecordingHTTPSServer = loopback_servers["https_server"]
    https_srv.recorded_requests.clear()
    https_srv.flaky_calls = 0
    https_srv.flaky_503_calls = 0

    # Warning when auth=None + unused client close
    with pytest.warns(UserWarning, match="without 'auth'"):
        no_auth_client = Client(config=Config(api_url=https_url, verify=ca_path))
    no_auth_client.close()

    # trust_env=False must ignore HTTPS_PROXY on real TLS requests
    dead_proxy = f"http://127.0.0.1:{unused_loopback_port()}"
    monkeypatch.setenv("HTTPS_PROXY", dead_proxy)
    monkeypatch.setenv("https_proxy", dead_proxy)

    with Client(
        auth=("pub", "priv"),
        config=Config(
            api_url=https_url,
            verify=ca_path,
            max_retries=2,
            trust_env=False,
            enable_security_audit=True,
        ),
    ) as client:
        # Introspection & wrappers
        assert "contact" in client.available_endpoints
        assert "Client" in repr(client)
        assert "Mailjet Client" in str(client)
        assert "send_v31" in dir(client)
        assert "Endpoint" in repr(client.contact)
        assert client.contact._resolve_registry_route(https_url.rstrip("/"), "v3", None, None)[0].endswith(
            "/REST/contact"
        )
        assert client.contact._resolve_dynamic_route(https_url.rstrip("/"), "v3", None, None)[0].endswith(
            "/REST/contact"
        )
        assert client.contact._build_headers()["Content-Type"] == "application/json"
        assert Endpoint._cast_query_param(0, "7") == 7
        assert BaseClient._compute_retry_delay(0, "1") == 1.0
        BaseClient._reset_stream_pointers(None, None)
        assert BaseClient._extract_error_detail(None, "oops") == ": oops"
        with pytest.raises(ApiError):
            BaseClient._handle_api_error(RuntimeError("boom"))
        BaseClient._extract_telemetry({"CustomID": "cid-1"}, None)

        # Private / typo attribute checks & cached _resolve_endpoint
        with pytest.raises(AttributeError):
            _ = client._private_attr
        with pytest.raises(AttributeError):
            client._validate_endpoint_name("_private_attr")
        with pytest.raises(AttributeError, match="Did you mean 'send'"):
            _ = client.snd
        assert client._resolve_endpoint("contact", Endpoint) is client.contact

        # BaseClient._log_request
        ok_resp = client.contact.get(filters={"Keep": "yes", "Drop": None})
        BaseClient._log_request("GET", https_url, ok_resp, "trace123")
        assert https_srv.recorded_requests[-1]["query"] == {"Keep": ["yes"]}

        # Copy & Deepcopy preserve config/auth with isolated fresh session
        shallow_copy = copy.copy(client)
        deep_copy = copy.deepcopy(client)
        try:
            assert shallow_copy._session is None
            assert deep_copy._session is None
            assert shallow_copy.ping() is True
            assert deep_copy.ping() is True
        finally:
            shallow_copy.close()
            deep_copy.close()

        # Route variants: v4, v1, action_id, missing id/action_id, deprecated routes, ambiguous templates
        assert client.contacts.get().json()["path"] == "/v4/contacts"
        assert client.tokens.get().json()["path"] == "/v1/REST/tokens"
        assert client.template_content_by_type.get(id=5, action_id="html").json()["path"] == (
            "/v1/REST/templates/5/contents/types/html"
        )
        with pytest.raises(ValueError, match="requires an 'id'"):
            client.template_detailcontent.get()
        with pytest.raises(ValueError, match="requires an 'action_id'"):
            client.template_content_by_type.get(id=5)

        with pytest.warns(DeprecationWarning, match="deprecated"):
            assert client.newsletter.get().status_code == 200
        with pytest.warns(DeprecationWarning, match="Ambiguity"):
            assert client.templates.get().status_code == 200
        assert client.SEND.create(data={"k": "v"}).json()["path"] == "/v3/send"
        assert client.customjob_csvdata.get(id=7).json()["path"] == "/v3/DATA/customjob/7/CSVData/text:plain"

        # CRUD verbs: create (+json, MappingProxyType, list payload, files stripping json), update, patch, delete
        r_plus_json = client.contact.create(
            headers={"content-type": "application/vnd.api+json"},
            data=types.MappingProxyType({"Email": "proxy@example.com"}),
        )
        assert r_plus_json.status_code == 201
        assert "idempotency-key" in https_srv.recorded_requests[-1]["headers"]

        r_explicit_idem = client.contact.create(
            headers={"Idempotency-Key": "manual-key-1"},
            data=[{"Email": "list@example.com"}],
        )
        assert r_explicit_idem.status_code == 201
        assert https_srv.recorded_requests[-1]["headers"]["idempotency-key"] == "manual-key-1"

        r_file = client.data_images.create(
            files={"file": ("logo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")},
        )
        assert r_file.status_code == 201
        assert "multipart/form-data" in https_srv.recorded_requests[-1]["headers"]["content-type"]

        r_file_txt = client.data_images.create(
            headers={"X-Tag": "v1", "Content-Type": "text/plain"},
            files={"file": ("note.txt", io.BytesIO(b"hello"), "text/plain")},
        )
        assert r_file_txt.status_code == 201

        # Deprecated ensure_ascii & data_encoding
        with pytest.warns(DeprecationWarning, match="deprecated"):
            r_enc = client.contact.create(
                data={"Email": "café@example.com"},
                ensure_ascii=False,
                data_encoding="utf-8",
            )
        assert r_enc.status_code == 201
        with pytest.warns(DeprecationWarning, match="deprecated"):
            assert client.contact.create(data="raw-string", ensure_ascii=True).status_code == 201

        upd_resp = client.contact.update(id=42, data={"Name": "Updated"})
        patch_resp = client.contact.patch(id=42, data={"Name": "Patched"})
        del_resp = client.contact.delete(id=42)
        assert upd_resp.status_code == 200
        assert patch_resp.json()["Data"][0]["Patched"] is True
        assert del_resp.status_code == 204
        with pytest.raises(ValueError, match="non-empty"):
            client.contact.patch(id="")
        with pytest.raises(ValueError, match="non-empty"):
            client.contact.delete(id="  ")

        # 204, 205, 304, 302
        assert client.nocontent.get().status_code == 204
        assert client.resetcontent.get().status_code == 205
        assert client.notmodified.get().status_code == 304
        assert client.redirect.get().status_code == 302

        # Deprecated module-level parse_response & logging_handler
        with pytest.warns(DeprecationWarning, match="parse_response"):
            assert parse_response(r_plus_json)["Count"] == 1
        bad_json_resp = client.contact.get(filters={"bad_json": "1"})
        with pytest.warns(DeprecationWarning, match="parse_response"):
            assert parse_response(bad_json_resp) == "not-valid-json"
        with pytest.warns(DeprecationWarning, match="logging_handler"):
            logging_handler(client)

        # Stream pagination: natural termination (max_items=None), max_items=0, and _extract_stream_page without raise_for_status
        assert list(client.contact.stream(chunk_size=2, max_items=0)) == []
        assert [item["ID"] for item in client.contact.stream(chunk_size=2)] == [1, 2, 3]
        assert list(client.contact.stream(chunk_size=2, filters={"empty_stream": "1"})) == []

        class _NoRaiseResp:
            status_code = 200
            text = '{"Data":[{"ID":7}]}'

            def json(self) -> dict[str, Any]:
                return {"Data": [{"ID": 7}]}

        assert client.contact._extract_stream_page(_NoRaiseResp()) == [{"ID": 7}]

        # Real socket 503 retry recovery exercising JitterRetry.get_backoff_time()
        r_503 = client.flaky503.get()
        assert r_503.status_code == 200
        assert https_srv.flaky_503_calls == 2

        # Redirect rejection & timeout config fallback
        with pytest.raises(ValueError, match="Redirects are strictly disabled"):
            client.contact.get(allow_redirects=True)
        with pytest.raises(ValueError, match="Redirects are strictly disabled"):
            client._normalize_request_parts({}, None, {"follow_redirects": True})

        with pytest.raises(ValueError, match="strictly positive"):
            client.contact.get(timeout=-1)

        client.config.timeout = -5
        with pytest.raises(ValueError, match="strictly positive"):
            client.contact.get()
        assert client.config.timeout > 0

    # Default CA bundle (verify=True) and untrusted CA must fail TLS verification closed
    with Client(auth=("pub", "priv"), api_url=https_url, verify=True, max_retries=0) as default_ca_sync:
        with pytest.raises(CriticalApiError):
            default_ca_sync.contact.get()
    with Client(auth=("pub", "priv"), api_url=https_url, verify=untrusted_ca, max_retries=0) as bad_ca_sync:
        with pytest.raises(CriticalApiError):
            bad_ca_sync.contact.get()

    # Closed client session behavior & context manager re-entry
    closed_sess = client.session
    assert closed_sess.auth is None
    assert dict(closed_sess.headers) == {}
    client.session = None
    with client as reopened:
        assert reopened.ping() is True

    # dry_run=True and auto_idempotency_mode uuid4 / off
    with Client(
        auth="bearer_tok",
        config=Config(api_url=https_url, verify=ca_path, dry_run=True, auto_idempotency_mode="off"),
    ) as dry_client:
        pre_count = len(https_srv.recorded_requests)
        dry_resp = dry_client.contact.create(data={"Email": "dry@example.com"})
        assert dry_resp.status_code == 200
        assert dry_resp.json()["DryRun"] is True
        assert len(https_srv.recorded_requests) == pre_count

    with Client(
        auth="bearer_tok",
        config=Config(api_url=https_url, verify=ca_path, auto_idempotency_mode="uuid4", max_retries=0),
    ) as uuid_client:
        assert uuid_client.contact.create(data={"Email": "u@example.com"}).status_code == 201
        assert len(https_srv.recorded_requests[-1]["headers"]["idempotency-key"]) == 36

    with Client(
        auth="bearer_tok",
        config=Config(api_url=https_url, verify=ca_path, auto_idempotency_mode="off", max_retries=0),
    ) as off_client:
        assert off_client.contact.create(data={"Email": "off@example.com"}).status_code == 201
        assert "idempotency-key" not in https_srv.recorded_requests[-1]["headers"]

    # warn_unclosed ResourceWarning + uninitialized Client.__new__
    uninit = Client.__new__(Client)
    uninit._warn_if_unclosed()

    warn_c = Client(auth=("pub", "priv"), api_url=https_url, verify=ca_path, warn_unclosed=True)
    _ = warn_c.session
    with pytest.warns(ResourceWarning, match="Unclosed Mailjet Client"):
        warn_c._warn_if_unclosed()
    warn_c.close()

    # Plain HTTP real loopback socket integration
    with Client(auth=("pub", "priv"), api_url=http_url, max_retries=0) as http_client:
        assert http_client.ping() is True
        assert http_client.contact.create(data={"Email": "http@example.com"}).status_code == 201
