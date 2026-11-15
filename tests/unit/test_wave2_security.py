"""Unit tests covering Wave 2 transport, redaction, routing, and streaming hardening."""

from __future__ import annotations

import base64
import errno
import logging
import ssl
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests
from requests.exceptions import RequestException

from mailjet_rest.builders import ChunkedStreamer
from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.utils.guardrails import (
    RedactingFilter,
    SecretAuth,
    SecureHTTPAdapter,
    SecurityGuard,
)


def _fake_conn() -> Any:
    conn = MagicMock()
    conn.ca_certs = "initial"
    conn.ca_cert_dir = "initial_dir"
    conn.ssl_context = None
    conn.cert_file = None
    conn.key_file = None
    return conn


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


def test_ssrf_post_init_mutation_and_redirect_blocked(monkeypatch: pytest.MonkeyPatch) -> None:
    """Post-init api_url SSRF mutation and allow_redirects=True are blocked."""
    client = Client(auth=("pub_key", "priv_key"))
    client.config.api_url = "https://evil.example.com/"
    with pytest.raises(ValueError, match="not permitted"):
        client.api_call("GET", "https://evil.example.com/v3/REST/contact")

    clean_client = Client(auth=("pub_key", "priv_key"))
    with pytest.raises(ValueError, match="Redirects are strictly disabled"):
        clean_client.api_call("GET", "https://api.mailjet.com/v3/REST/contact", allow_redirects=True)

    with pytest.raises(ValueError, match="Redirects are strictly disabled"):
        clean_client._execute_request(
            "GET", "https://api.mailjet.com/v3/REST/contact", {}, None, None, 10, allow_redirects=True
        )

    redirect_resp = requests.Response()
    redirect_resp.status_code = 302
    monkeypatch.setattr(clean_client.session, "request", MagicMock(return_value=redirect_resp))

    with patch("sys.audit") as mock_audit:
        res = clean_client._execute_request("GET", "https://api.mailjet.com/v3/REST/contact", {}, None, None, 10)
        assert res.status_code == 302
        mock_audit.assert_any_call(
            "mailjet.security.unexpected_redirect", "https://api.mailjet.com/v3/REST/contact", 302
        )


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


def test_secret_auth_constant_time_and_str() -> None:
    """SecretAuth provides redacted __str__ and constant-time equality."""
    a1 = SecretAuth(("k1", "s1"))
    a2 = SecretAuth(("k1", "s1"))
    assert str(a1) == "SecretAuth(***REDACTED***)"
    assert a1 == a2
    assert a1 == ("k1", "s1")
    assert a1 != ("k1", "wrong")
    assert a1 != ("k1",)


def test_redacting_filter_exc_info_exc_text_and_sensitive_keys() -> None:
    """RedactingFilter scrubs exception info, exc_text, dict keys, and extra fields."""
    flt = RedactingFilter()
    try:
        raise RuntimeError("boom Authorization: Bearer super_secret_token_99")
    except RuntimeError:
        exc_info = sys.exc_info()

    record = logging.LogRecord("test", logging.ERROR, "mod.py", 10, "failed", (), exc_info)
    record.api_secret = "raw_unprefixed_secret_value"  # type: ignore[attr-defined]
    record.extra_payload = {"password": "my_db_password", "enabled": True, "nullable": None}  # type: ignore[attr-defined]

    flt.filter(record)
    assert record.exc_info is None
    assert record.exc_text is not None
    assert "super_secret_token_99" not in record.exc_text
    assert "********" in record.exc_text
    assert getattr(record, "api_secret") == "********"
    assert getattr(record, "extra_payload")["password"] == "********"
    assert getattr(record, "extra_payload")["enabled"] is True
    assert getattr(record, "extra_payload")["nullable"] is None


def test_shared_sibling_fingerprint_and_self_closing_spamguard() -> None:
    """Backtracking fingerprint distinguishes shared sibling dicts from cycles; self-closing tags are checked."""
    shared = {"email": "user@example.com"}
    p_shared = {"a": shared, "b": shared}
    p_distinct = {"a": {"email": "user@example.com"}, "b": {"email": "user@example.com"}}
    assert SecurityGuard.generate_payload_fingerprint(p_shared) == SecurityGuard.generate_payload_fingerprint(
        p_distinct
    )

    with pytest.raises(ValueError, match="blocked script/event execution tags|executable Javascript/XSS"):
        SecurityGuard.analyze_html_safety("<img src='cid:logo' onerror='x'/>")


def test_attachment_symlink_and_chunked_streamer_safeguards(tmp_path: Path) -> None:
    """Symlinks, missing tempdir files, and query/fragment delimiters are rejected."""
    secret_target = tmp_path / "real.txt"
    secret_target.write_bytes(b"hello world")
    symlink_path = tmp_path / "link.txt"
    symlink_path.symlink_to(secret_target)

    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        SecurityGuard.validate_attachment_path(symlink_path, safe_base_dir=tmp_path)

    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        ChunkedStreamer.encode_file(symlink_path, safe_base_dir=tmp_path)

    with pytest.raises(ValueError, match="Null byte"):
        SecurityGuard.validate_attachment_path("bad\x00path.txt", safe_base_dir=tmp_path)

    missing_temp = Path(tmp_path) / "nonexistent.txt"
    with pytest.raises(FileNotFoundError):
        SecurityGuard.validate_attachment_path(missing_temp)

    # Lossless base64 ASCII encoding via pinned fd
    b64 = ChunkedStreamer.encode_file(secret_target, chunk_size=4, safe_base_dir=tmp_path)
    assert base64.b64decode(b64) == b"hello world"

    # Directory & oversize limits fail closed
    with pytest.raises(FileNotFoundError):
        ChunkedStreamer.encode_file(tmp_path, safe_base_dir=tmp_path.parent)

    with pytest.raises(ValueError, match="exceeds safe threshold"):
        ChunkedStreamer.encode_file(secret_target, safe_base_dir=tmp_path, max_bytes=4)

    with patch("os.open", side_effect=OSError(errno.ELOOP, "Too many levels of symbolic links")):
        with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
            ChunkedStreamer.encode_file(secret_target, safe_base_dir=tmp_path)


def test_routing_query_fragment_delete_5xx_and_warning_stacklevel() -> None:
    """Query/fragment delimiters, blank/bool delete IDs, 5xx MailjetApiError, and external stacklevel work."""
    with pytest.raises(ValueError, match="Query or fragment delimiters"):
        SecurityGuard.sanitize_segment("123?admin=true")

    with pytest.raises(ValueError, match="Query or fragment delimiters"):
        SecurityGuard.sanitize_segment("123%23frag")

    client = Client(auth=("pub_key", "priv_key"))
    for bad_id in ("", "   ", None, True, False):
        with pytest.raises(ValueError, match="Endpoint.delete\\(\\) requires"):
            client.contact.delete(id=bad_id)  # type: ignore[arg-type]

    resp_503 = MagicMock(status_code=503, text="Service Unavailable")
    resp_503.json.side_effect = ValueError("not json")
    with pytest.raises(MailjetApiError) as exc_info:
        Client._handle_api_error(RequestException("503", response=resp_503))
    assert exc_info.value.status_code == 503
    assert exc_info.value.response_body == "Service Unavailable"

    with pytest.warns(DeprecationWarning) as caught:
        client.newsletter._build_url()
    assert Path(caught[0].filename).resolve() == Path(__file__).resolve()
