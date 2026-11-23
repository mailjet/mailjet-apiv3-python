"""Unit tests for TLS transport security, SSL context caching, and SecretAuth."""

from __future__ import annotations

import base64
import os
import socket
import ssl
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.transport_security import (
    _KEEPALIVE_OPTION,
    _KEEPALIVE_SOCKET_OPTIONS,
    SecretAuth,
    SecureHTTPAdapter,
    _build_tls_context,
    _cached_ssl_context,
    _new_secure_ssl_context,
    build_ssl_context_with_cert,
    coerce_httpx2_timeout,
    get_secure_ssl_context,
    resolve_tls_verify,
)


def _fake_conn() -> Any:
    conn = MagicMock()
    conn.ca_certs = "initial"
    conn.ca_cert_dir = "initial_dir"
    conn.ssl_context = None
    conn.cert_file = None
    conn.key_file = None
    return conn


class _BytesPath:
    """PathLike returning bytes from __fspath__ to exercise TypeError paths."""

    def __fspath__(self) -> bytes:
        return b"/tmp/ca.pem"


def test_ssl_context_cache_and_rotation_invalidation(tmp_path: Path) -> None:
    """get_secure_ssl_context caches identical inputs and reloads when CA file changes."""
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy-ca-v1", encoding="utf-8")

    fake_ctx_1 = MagicMock(spec=ssl.SSLContext)
    fake_ctx_2 = MagicMock(spec=ssl.SSLContext)
    _cached_ssl_context.cache_clear()

    with patch("ssl.create_default_context", side_effect=[fake_ctx_1, fake_ctx_2]) as mock_ctx:
        ctx_a = get_secure_ssl_context(str(ca_file))
        ctx_b = get_secure_ssl_context(str(ca_file))
        assert ctx_a is fake_ctx_1
        assert ctx_b is fake_ctx_1
        assert mock_ctx.call_count == 1

        # Simulate rotated CA bundle with different size and mtime
        ca_file.write_text("dummy-ca-rotated-v2-longer", encoding="utf-8")
        st = ca_file.stat()
        os.utime(ca_file, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))

        ctx_c = get_secure_ssl_context(str(ca_file))
        assert ctx_c is fake_ctx_2
        assert mock_ctx.call_count == 2

    _cached_ssl_context.cache_clear()


def test_secret_auth_precomputes_authorization_header() -> None:
    """SecretAuth pre-computes Basic Authorization header in __init__."""
    auth = SecretAuth(("my_key", "my_secret"))
    assert auth._auth_header.startswith("Basic ")
    req = requests.Request("GET", "https://api.mailjet.com/v3/REST/contact").prepare()
    auth(req)
    assert req.headers["Authorization"] == auth._auth_header


def test_transport_security_ssl_cert_timeout_and_secret_auth() -> None:
    """Cover client-cert SSLContext paths, timeout fallback, and SecretAuth validation."""
    ctx_default = build_ssl_context_with_cert(None, None)
    assert ctx_default is not None

    fake_ctx = MagicMock()
    with patch("mailjet_rest.utils.transport_security._new_secure_ssl_context", return_value=fake_ctx):
        assert build_ssl_context_with_cert(None, ("cert.pem", "key.pem")) is fake_ctx
        fake_ctx.load_cert_chain.assert_called_once_with(certfile="cert.pem", keyfile="key.pem")

        fake_ctx.reset_mock()
        assert build_ssl_context_with_cert(None, "single.pem") is fake_ctx
        fake_ctx.load_cert_chain.assert_called_once_with(certfile="single.pem")

        with pytest.raises(ValueError, match="certfile, keyfile"):
            build_ssl_context_with_cert(None, ("only-one",))  # type: ignore[arg-type]

        with pytest.raises(TypeError, match="Invalid 'cert' type"):
            build_ssl_context_with_cert(None, 123)  # type: ignore[arg-type]

    assert coerce_httpx2_timeout(SimpleNamespace(Timeout=MagicMock()), True) is True

    with pytest.raises(ValueError, match="2-tuple"):
        SecretAuth("bad")
    with pytest.raises(TypeError, match="must be strings"):
        SecretAuth((1, 2))

    auth = SecretAuth(("pub", "priv"))
    assert (auth == ("pub\ud800", "priv")) is False


def test_secret_auth_del_char_and_http_adapter_plain_http() -> None:
    """Reject DEL (0x7F) in SecretAuth and skip HTTPS isolation on plain HTTP URLs."""
    with pytest.raises(ValueError, match="forbidden control characters or CRLF"):
        SecretAuth(("bad\x7fkey", "secret"))

    # SecureHTTPAdapter skips HTTPS-only isolation on plain http URLs (localhost loop test)
    adapter = SecureHTTPAdapter()
    conn = MagicMock(ssl_context="unchanged", ca_certs="orig", ca_cert_dir="orig_dir")
    adapter.cert_verify(conn, "http://localhost/v3/send", True, None)
    assert conn.ssl_context == "unchanged"


def test_tls_verify_rejects_false_none_and_missing_ca(tmp_path: Path) -> None:
    """Verify=False/None and missing custom CA files fail closed across Config and Client."""
    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
        SecurityGuard.resolve_tls_verify(False)

    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
        Config(verify=False)

    client = Client(auth=("pub_key", "priv_key"))
    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
        client.api_call("GET", "https://api.mailjet.com/v3/REST/contact", verify=False)

    with pytest.raises(ValueError, match="TLS verification cannot be disabled"):
        client._execute_request("GET", "https://api.mailjet.com/v3/REST/contact", {}, None, None, 10, verify=None)

    missing_ca = tmp_path / "missing-ca.pem"
    with pytest.raises(ValueError, match="does not exist or is not a file"):
        Config(verify=missing_ca)

    with pytest.raises(TypeError, match="Invalid 'verify' type"):
        SecurityGuard.resolve_tls_verify(12345)


def test_custom_ca_bundle_isolated_context(tmp_path: Path) -> None:
    """Custom CA bundle path validates cleanly and isolates SecureHTTPAdapter SSLContext."""
    ca_one = tmp_path / "ca-one.pem"
    ca_two = tmp_path / "ca-two.pem"
    ca_one.write_text("dummy", encoding="utf-8")
    ca_two.write_text("dummy", encoding="utf-8")

    # Mock SSLContext creation so synthetic PEM content does not require OpenSSL X509 parsing
    mock_ctx_one = MagicMock(spec=ssl.SSLContext)
    mock_ctx_two = MagicMock(spec=ssl.SSLContext)
    mock_ctx_default = MagicMock(spec=ssl.SSLContext)

    with patch(
        "mailjet_rest.utils.transport_security._build_tls_context",
        side_effect=[mock_ctx_one, mock_ctx_two, mock_ctx_default],
    ) as build_ctx:
        cfg = Config(verify=ca_one)
        assert cfg.verify == str(ca_one)

        adapter = SecureHTTPAdapter(ca_bundle=str(ca_one))
        conn1 = _fake_conn()
        adapter.cert_verify(conn1, "https://api.mailjet.com/v3/send", str(ca_one), None)
        assert conn1.ssl_context is mock_ctx_one
        assert conn1.ca_certs is None
        assert conn1.ca_cert_dir is None

        conn2 = _fake_conn()
        adapter.cert_verify(conn2, "https://api.mailjet.com/v3/send", str(ca_two), None)
        assert conn2.ssl_context is mock_ctx_two
        assert conn2.ca_certs is None

        conn3 = _fake_conn()
        adapter.cert_verify(conn3, "https://api.mailjet.com/v3/send", True, None)
        assert conn3.ssl_context is mock_ctx_default
        assert build_ctx.call_count == 3


def test_secret_auth_constant_time_and_str() -> None:
    """SecretAuth provides redacted __str__ and constant-time equality."""
    a1 = SecretAuth(("k1", "s1"))
    a2 = SecretAuth(("k1", "s1"))
    assert str(a1) == "SecretAuth(***REDACTED***)"
    assert a1 == a2
    assert a1 == ("k1", "s1")
    assert a1 != ("k1", "wrong")
    assert a1 != ("k1",)


def test_transport_security_verify_audit_and_errors(tmp_path: Path) -> None:
    """Verify resolve_tls_verify audit hooks, error messages, and boundary types."""
    audit_events: list[tuple[str, tuple[object, ...]]] = []

    def hook(event: str, args: tuple[object, ...]) -> None:
        if event == "mailjet.security.tls_disabled":
            audit_events.append((event, args))

    sys.addaudithook(hook)

    for bad_verify in (False, None):
        with pytest.raises(ValueError) as exc_info:
            resolve_tls_verify(bad_verify)
        assert (
            str(exc_info.value)
            == "Security Violation: Mailjet API TLS verification cannot be disabled (verify=False is forbidden)."
        )

    assert ("mailjet.security.tls_disabled", ("False",)) in audit_events
    assert ("mailjet.security.tls_disabled", ("None",)) in audit_events
    assert resolve_tls_verify(verify=True) is True

    with pytest.raises(TypeError) as bytes_exc:
        resolve_tls_verify(_BytesPath())  # type: ignore[arg-type]
    assert str(bytes_exc.value) == "Invalid CA bundle path type: expected str or os.PathLike[str], got bytes."

    for empty_or_ctrl in ("", "   ", f"{tmp_path}/bad\n.pem", f"{tmp_path}/bad\x00.pem"):
        with pytest.raises(ValueError) as val_exc:
            resolve_tls_verify(empty_or_ctrl)
        assert str(val_exc.value) == "Invalid CA bundle path: must be a non-empty path without control characters."

    missing = tmp_path / "missing.pem"
    with pytest.raises(ValueError) as missing_exc:
        resolve_tls_verify(str(missing))
    assert str(missing_exc.value) == f"Custom CA bundle path does not exist or is not a file: {missing}"

    with pytest.raises(ValueError) as dir_exc:
        resolve_tls_verify(tmp_path)
    assert str(dir_exc.value) == f"Custom CA bundle path does not exist or is not a file: {tmp_path}"

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy", encoding="utf-8")
    assert resolve_tls_verify(ca_file) == str(ca_file)

    with pytest.raises(TypeError) as int_exc:
        resolve_tls_verify(123)
    assert str(int_exc.value) == "Invalid 'verify' type: expected bool, str, or PathLike, got int."


def test_ssl_context_cache_invalidation_adapter_and_secret_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSLContext caching by mtime/size, adapter cert_verify isolation, and SecretAuth equality/hashing."""
    ctx_default_1 = get_secure_ssl_context()
    ctx_default_2 = _build_tls_context(None)
    assert ctx_default_1 is ctx_default_2
    assert ctx_default_1.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx_default_1.check_hostname is True
    assert ctx_default_1.verify_mode == ssl.CERT_REQUIRED
    assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) == _KEEPALIVE_OPTION
    assert _KEEPALIVE_OPTION in _KEEPALIVE_SOCKET_OPTIONS

    # Generate valid self-signed CA cert via cryptography or mock load_verify_locations/create_default_context
    ca_one = tmp_path / "ca1.pem"
    ca_two = tmp_path / "ca2.pem"
    ca_one.write_text("pem-a", encoding="utf-8")
    ca_two.write_text("pem-b", encoding="utf-8")

    fake_created: list[tuple[str | None, MagicMock]] = []

    def fake_create_default_context(*, cafile: str | None = None) -> MagicMock:
        ctx = MagicMock(spec=ssl.SSLContext)
        ctx.options = 0
        ctx.cafile_seen = cafile
        fake_created.append((cafile, ctx))
        return ctx

    monkeypatch.setattr("mailjet_rest.utils.transport_security.ssl.create_default_context", fake_create_default_context)
    # Clear lru_cache so mocked context creation executes deterministically
    _cached_ssl_context.cache_clear()
    try:
        first = get_secure_ssl_context(str(ca_one))
        second = get_secure_ssl_context(str(ca_one))
        assert first is second
        assert getattr(first, "cafile_seen") == str(ca_one)

        # Updating size + mtime invalidates cache and yields a fresh context
        ca_one.write_text("pem-a-updated-length", encoding="utf-8")
        st_now = ca_one.stat()
        os.utime(ca_one, ns=(st_now.st_atime_ns, st_now.st_mtime_ns + 1_000_000))
        third = get_secure_ssl_context(str(ca_one))
        assert third is not first

        adapter = SecureHTTPAdapter(ca_bundle=str(ca_one))
        assert adapter._ca_bundle == str(ca_one)
        assert SecureHTTPAdapter._get_secure_ssl_context(str(ca_two)) is get_secure_ssl_context(str(ca_two))

        conn = SimpleNamespace(
            ssl_context=None, ca_certs="stale", ca_cert_dir="stale_dir", assert_hostname=None, cert_reqs=None
        )
        adapter.cert_verify(conn, "HTTPS://api.example.com", verify=True, cert=None)
        assert conn.ssl_context is not adapter._ssl_context
        assert conn.ca_certs is None
        assert conn.ca_cert_dir is None

        conn_same = SimpleNamespace(
            ssl_context=None, ca_certs="stale", ca_cert_dir="stale_dir", assert_hostname=None, cert_reqs=None
        )
        adapter.cert_verify(conn_same, "https://api.example.com", verify=str(ca_one), cert=None)
        assert conn_same.ssl_context is adapter._ssl_context
        assert conn_same.ca_certs is None
        assert conn_same.ca_cert_dir is None
    finally:
        _cached_ssl_context.cache_clear()

    auth_a1 = SecretAuth(("key1", "sec1"))
    auth_a2 = SecretAuth(("key1", "sec1"))
    auth_diff_key = SecretAuth(("key2", "sec1"))
    auth_diff_sec = SecretAuth(("key1", "sec2"))

    req = requests.Request("GET", "https://api.example.com").prepare()
    out_req = auth_a1(req)
    assert out_req is req
    expected_hdr = "Basic " + base64.b64encode(b"key1:sec1").decode("ascii")
    assert out_req.headers["Authorization"] == expected_hdr

    assert auth_a1 == auth_a2
    assert hash(auth_a1) == hash(auth_a2)
    assert auth_a1 != auth_diff_key
    assert auth_a1 != auth_diff_sec
    assert auth_a1 == ("key1", "sec1")
    assert auth_a1 != ("key1", "other")
    assert auth_a1 != "not-an-auth"

    with pytest.raises(TypeError) as idx_exc:
        _ = auth_a1[0]
    assert str(idx_exc.value) == "Credential extraction via indexing is blocked for security (CWE-316)."

    with pytest.raises(TypeError) as iter_exc:
        list(auth_a1)
    assert str(iter_exc.value) == "Credential extraction via iteration is blocked for security (CWE-316)."


def test_secret_auth_rejects_non_latin1_with_clean_value_error() -> None:
    """SecretAuth must raise explicit ValueError (not raw UnicodeEncodeError) for non-Latin-1 credentials."""
    with pytest.raises(ValueError, match="Latin-1") as exc_info:
        SecretAuth(("ключ", "secret"))
    assert type(exc_info.value) is ValueError


def test_transport_security_op_no_compression_and_timeout_tuple() -> None:
    """Preserve existing SSL options with OP_NO_COMPRESSION and map tuple timeouts for httpx2."""
    # transport_security: OP_NO_COMPRESSION preserves existing flags & coerce_httpx2_timeout tuple args
    fake_ctx = SimpleNamespace(minimum_version=None, check_hostname=False, verify_mode=None, options=0xFF)
    fake_ctx.load_verify_locations = MagicMock()
    with patch("mailjet_rest.utils.transport_security.ssl.create_default_context", return_value=fake_ctx):
        res_ctx = _new_secure_ssl_context(None)
    assert res_ctx.options == (0xFF | getattr(ssl, "OP_NO_COMPRESSION", 0))

    recorded_timeouts: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    class _FakeTimeout:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            recorded_timeouts.append((args, kwargs))

    coerce_httpx2_timeout(SimpleNamespace(Timeout=_FakeTimeout), (2.5, 7.5))
    assert recorded_timeouts == [((7.5,), {"connect": 2.5, "read": 7.5, "write": 7.5, "pool": 2.5})]
