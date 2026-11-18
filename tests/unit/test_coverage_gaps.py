"""Targeted unit tests closing branch and statement coverage gaps across utils."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.errors import ValidationError
from mailjet_rest.utils.filesystem_security import (
    validate_attachment_path,
    validate_multipart_files,
)
from mailjet_rest.utils.html_guard import _inspect_starttag, analyze_html_safety, build_spam_guard_parser
from mailjet_rest.utils.retry import (
    _check_async_retry_response,
    compute_retry_delay,
    parse_retry_after_http_date,
    reset_stream_pointers,
    run_async_with_retries,
)
from mailjet_rest.utils.telemetry import record_debug_telemetry
from mailjet_rest.utils.transport_security import (
    SecretAuth,
    build_ssl_context_with_cert,
    coerce_httpx2_timeout,
)


def test_filesystem_security_bytes_oserror_and_multipart_edges(tmp_path: Path) -> None:
    """Cover bytes NUL rejection, inspect OSError, and non-standard multipart specs."""
    sample = tmp_path / "attach.txt"
    sample.write_text("ok", encoding="utf-8")

    assert validate_attachment_path(bytes(sample), safe_base_dir=tmp_path) == sample.resolve()  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Null byte"):
        validate_attachment_path(b"/tmp/evil\x00.txt")  # type: ignore[arg-type]

    with patch.object(Path, "resolve", side_effect=RuntimeError("symlink loop")):
        with pytest.raises(ValueError, match="Invalid attachment path"):
            validate_attachment_path(sample)

    with patch.object(Path, "exists", side_effect=OSError("io failure")):
        with pytest.raises(ValueError, match="Cannot inspect attachment path"):
            validate_attachment_path(sample, safe_base_dir=tmp_path)

    # None, non-collection, malformed entry, and None/int fields in multipart spec
    validate_multipart_files(None, header_sanitizer=dict)
    validate_multipart_files(123, header_sanitizer=dict)
    validate_multipart_files(["bad-entry", ("file", (None, b"abc", None, {"X-A": "1"}))], header_sanitizer=dict)
    validate_multipart_files([(123, (123, b"abc"))], header_sanitizer=dict)


def test_html_guard_endtag_comment_limits_and_script_inspection() -> None:
    """Cover handle_endtag, handle_comment, max_html_size, max_tag_count, and executable tags."""
    parser_cls = build_spam_guard_parser()
    report = analyze_html_safety("<div>hello</div><!-- note -->", parser_factory=parser_cls)
    assert report == {"is_safe": True, "issues": []}

    with pytest.raises(ValueError, match="exceeds maximum safe length"):
        analyze_html_safety("a" * 50, parser_factory=parser_cls, max_html_size=10)

    with pytest.raises(ValidationError, match="maximum tag limit"):
        analyze_html_safety("<p>a</p><p>b</p>", parser_factory=parser_cls, max_tag_count=2)

    parser = parser_cls()
    _inspect_starttag(parser, "script", [("src", "x")])
    assert parser.has_script is True
    assert parser.is_safe is False
    assert parser.issues == ["Blocked executable tag: <script>"]


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


def test_telemetry_debug_success_logging(caplog: pytest.LogCaptureFixture) -> None:
    """Cover record_debug_telemetry and log_api_response DEBUG success branch."""
    test_log = logging.getLogger("mailjet_rest.test_telemetry")
    with caplog.at_level(logging.DEBUG, logger="mailjet_rest.test_telemetry"):
        record_debug_telemetry(
            test_log,
            "GET",
            "https://api.mailjet.com/v3/REST/contact",
            SimpleNamespace(status_code=200),
            {"CustomID": "trace-1"},
            None,
        )
    assert "API Success 200" in caplog.text
    assert "CustomID=trace-1" in caplog.text


def test_retry_http_date_stream_and_async_branches() -> None:
    """Cover naive HTTP-date, whitespace/NaN Retry-After, non-seekable stream, and invalid max_retries."""
    naive_delay = parse_retry_after_http_date("Wed, 21 Oct 2015 07:28:00")
    assert naive_delay == 0.0

    assert compute_retry_delay(0, retry_after_header="   ") >= 0.0
    assert compute_retry_delay(0, retry_after_header="nan") >= 0.0
    assert compute_retry_delay(0, retry_after_header="-5") >= 0.0

    non_seekable = SimpleNamespace(seek=MagicMock(), seekable=lambda: False, closed=False)
    reset_stream_pointers(non_seekable, None)
    non_seekable.seek.assert_not_called()

    closed = False

    async def _aclose() -> None:
        nonlocal closed
        closed = True

    async def _exercise_async() -> None:
        resp = SimpleNamespace(status_code=429, headers={"Retry-After": "0"}, is_closed=False, aclose=_aclose)
        delay = await _check_async_retry_response(
            resp,
            0,
            2,
            "GET",
            "https://api.mailjet.com/v3/REST/contact",
            log=logging.getLogger("mailjet_rest.test_retry"),
            transient_status_codes=frozenset({429}),
            max_delay=60.0,
        )
        assert delay == 0.0
        assert closed is True

        fake_httpx2 = SimpleNamespace(
            TimeoutException=TimeoutError,
            NetworkError=OSError,
            RemoteProtocolError=RuntimeError,
            ProxyError=ConnectionError,
            UnsupportedProtocol=ValueError,
            DecodingError=UnicodeError,
        )
        with pytest.raises(ValueError, match="non-negative integer"):
            await run_async_with_retries(
                lambda: asyncio.sleep(0),
                fake_httpx2,
                method="GET",
                url="https://api.mailjet.com/v3/REST/contact",
                raw_retries=-1,
                max_retries_limit=20,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({429}),
                max_delay=60.0,
                data=None,
                files=None,
                log=logging.getLogger("mailjet_rest.test_retry"),
            )

    asyncio.run(_exercise_async())


def test_client_getattr_shutdown_guard_for_del(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify __del__/__getattr__ raises AttributeError instead of ImportError when sys.meta_path is None."""
    import sys  # ruff: ignore[import-outside-top-level]
    from mailjet_rest.client import AsyncClient, Client  # ruff: ignore[import-outside-top-level]

    partial_sync = Client.__new__(Client)
    partial_async = AsyncClient.__new__(AsyncClient)
    monkeypatch.setattr(sys, "meta_path", None)

    # _warn_if_unclosed must swallow AttributeError cleanly rather than leaking ImportError
    partial_sync._warn_if_unclosed()  # ruff: ignore[private-member-access]
    partial_async._warn_if_unclosed()  # ruff: ignore[private-member-access]
