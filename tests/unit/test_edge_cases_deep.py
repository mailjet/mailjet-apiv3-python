"""Deep edge-case unit tests pushing branch coverage >93% across all SDK modules."""

from __future__ import annotations

import asyncio
import importlib
import io
import logging
import os
import types
import warnings
from pathlib import Path
from typing import Any, NamedTuple
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests

from mailjet_rest.builders import ChunkedStreamer, MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.client import AsyncClient, BaseClient, Client, _httpx2
from mailjet_rest.config import Config
from mailjet_rest.errors import ApiError, ValidationError, extract_error_detail, raise_mapped_http_error
from mailjet_rest.utils.filesystem_security import check_file_size, validate_attachment_path, validate_multipart_files
from mailjet_rest.utils.guardrails import RedactingFilter, SecretAuth, SecureHTTPAdapter, SecurityGuard
from mailjet_rest.utils.html_guard import build_spam_guard_parser
from mailjet_rest.utils.routing import external_stacklevel, resolve_dynamic_route


# ==========================================
# 1. errors.py & guardrails.py Edge Cases
# ==========================================


def test_errors_v31_nested_extraction_and_non_error_status() -> None:
    """Cover v3.1 Messages/Errors branches, malformed JSON fallback, and unexpected non-4xx status."""
    resp_v31 = MagicMock(status_code=400, text="raw fallback")
    resp_v31.json.return_value = {"Messages": [{"Errors": [{"ErrorMessage": "bad recipient\r\nforged"}]}]}
    detail = extract_error_detail(resp_v31, "raw fallback")
    assert detail == ": bad recipient  forged"

    edge_payloads: tuple[dict[str, Any], ...] = (
        {"Messages": ["not-a-dict"]},
        {"Messages": [{"Errors": []}]},
        {"Messages": [{"Errors": ["not-a-dict"]}]},
    )
    for payload in edge_payloads:
        resp_edge = MagicMock(status_code=400, text="")
        resp_edge.json.return_value = payload
        assert extract_error_detail(resp_edge, "") == ""

    resp_ok = MagicMock(status_code=200, text="ok")
    resp_ok.json.side_effect = ValueError("not json")
    with pytest.raises(ApiError, match="An unexpected Mailjet API network error occurred"):
        raise_mapped_http_error(resp_ok, RuntimeError("transport hiccup"))


def test_redacting_filter_deep_types_recursion_and_failsafe() -> None:
    """Cover NamedTuple, model_dump, __dict__, slotted __str__, failing __str__, sets, depth limit, and failsafe."""
    flt = RedactingFilter()

    class _CredTuple(NamedTuple):
        api_key: str
        note: str

    class _ModelObj:
        def model_dump(self) -> dict[str, str]:
            return {"api_secret": "dump_secret", "Authorization": "Bearer dump_tok_99"}  # pragma: allowlist secret

    class _DictObj:
        def __init__(self) -> None:
            self.token = "dict_tok_88"
            self.ok = 42

    class _SlottedStrObj:
        __slots__ = ()

        def __str__(self) -> str:
            return "Authorization: Bearer slotted_tok_77"

    class _BadStrObj:
        __slots__ = ()

        def __str__(self) -> str:
            raise ValueError("cannot stringify")

    named = _CredTuple("Authorization: Bearer abc_secret", "token=def_secret")
    redacted_named = flt._deep_redact(named)
    assert isinstance(redacted_named, _CredTuple)
    assert tuple(redacted_named) == ("Authorization: Bearer ********", "token=********")

    model_res = flt._deep_redact(_ModelObj())
    assert model_res["api_secret"] == "********"
    assert model_res["Authorization"] == "********"

    dict_res = flt._deep_redact(_DictObj())
    assert dict_res["token"] == "********"
    assert dict_res["ok"] == 42

    assert flt._deep_redact(_SlottedStrObj()) == "Authorization: Bearer ********"
    assert flt._deep_redact(_BadStrObj()) == ""

    nested_sets = flt._deep_redact([{"Authorization: Bearer x1"}, frozenset({"Authorization: Bearer x2"})])
    assert isinstance(nested_sets, list)
    assert "Authorization: Bearer ********" in nested_sets[0]
    assert "Authorization: Bearer ********" in nested_sets[1]

    deep = {"a": {"b": {"c": {"d": {"e": {"f": "secret"}}}}}}
    assert flt._deep_redact(deep)["a"]["b"]["c"]["d"]["e"] == "[MAX_DEPTH_REACHED]"

    rec = logging.LogRecord("mailjet_rest", logging.ERROR, "", 0, "failed", (), None)
    rec.exc_text = "api_secret=topsecret_val"
    rec.exc_info = ()  # type: ignore[assignment]
    flt.filter(rec)
    assert "topsecret_val" not in (rec.exc_text or "")
    assert "********" in (rec.exc_text or "")

    with patch("mailjet_rest.utils.guardrails._get_secret_pattern", side_effect=RuntimeError("regex error")):
        assert flt._redact_str("Bearer secret") == "[REDACTION_FAILED_UNSAFE_STRING]"

    clean_rec = logging.LogRecord("mailjet_rest", logging.INFO, "", 0, "clean", (), None)
    assert flt.filter(clean_rec) is True

    faulty_record = logging.LogRecord("mailjet_rest", logging.INFO, "", 0, "token=abc", (), None)
    with patch.object(flt, "_redact_str", side_effect=RuntimeError("unexpected")):
        assert flt.filter(faulty_record) is True


def test_security_guard_validation_orjson_fallback_and_idn_edges(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover audit hook, target URL without base, proxy edges, orjson paths, timeout overflow, and IDNA errors."""
    with patch("sys.audit") as mock_audit:
        with Client(auth=("pub_key", "priv_key"), enable_security_audit=True) as audited:
            assert audited.config.enable_security_audit is True
        mock_audit.assert_any_call("mailjet.security.audit_enabled")

    SecurityGuard.validate_target_url("https://api.mailjet.com/v3/send", base_api_url=None)
    with pytest.raises(ValueError, match="forbidden control characters"):
        SecurityGuard.validate_target_url(
            "https://api.mailjet.com/v3/send\x00bad",
            base_api_url="https://api.mailjet.com/",
        )

    assert SecurityGuard.sanitize_log_trace("") == ""
    assert SecurityGuard.sanitize_segment(None) == ""
    with pytest.raises(ValueError, match="Excessive URL encoding"):
        SecurityGuard.sanitize_segment("%2525252e")
    with pytest.raises(ValueError, match="Template injection"):
        SecurityGuard.sanitize_segment("abc{{1+1}}")
    with pytest.raises(ValueError, match="XSS attempt"):
        SecurityGuard.sanitize_segment("<script>alert(1)<svg>")

    with pytest.raises(TypeError, match="Invalid proxy URL type"):
        SecurityGuard.check_request_security({"proxies": {"https": 123}})
    with pytest.raises(ValueError, match="forbidden control characters"):
        SecurityGuard.check_request_security({"proxies": "https://proxy.local:8080\x00"})
    with pytest.warns(UserWarning, match="Unencrypted HTTP proxy"):
        SecurityGuard.check_request_security({"proxies": "http://proxy.local"})
    # Host:port without scheme does not raise or warn
    with warnings.catch_warnings(record=True) as no_warn:
        warnings.simplefilter("always", UserWarning)
        SecurityGuard.check_request_security({"proxies": "proxy.local:8080"})
    assert not no_warn

    fake_orjson = types.SimpleNamespace(OPT_SORT_KEYS=1)

    def _orjson_dumps(obj: Any, *, option: int, default: Any) -> bytes:
        assert option == 1
        assert callable(default)
        if any(isinstance(k, int) for k in obj):
            raise TypeError("dict key must be str")
        return b'{"ok":1}'

    fake_orjson.dumps = _orjson_dumps
    monkeypatch.setattr("mailjet_rest.utils.guardrails._orjson", fake_orjson)
    assert SecurityGuard._canonical_json_bytes({"ok": 1}) == b'{"ok":1}'
    fallback = SecurityGuard._canonical_json_bytes({1: "one"})
    assert fallback == b'{"1":"one"}'

    with pytest.raises(ValueError, match="out of range"):
        SecurityGuard._validate_scalar_timeout(10**400)
    with pytest.warns(DeprecationWarning, match="infinite socket blocking"):
        with pytest.raises(TypeError, match="valid numeric values"):
            SecurityGuard.validate_timeout((None, 5.0))  # type: ignore[arg-type]
    with patch.object(SecurityGuard, "_validate_scalar_timeout", side_effect=OverflowError("huge")):
        with pytest.raises(ValueError, match="out of range"):
            SecurityGuard.validate_timeout(5)

    assert SecurityGuard.normalize_domain("") == ""
    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain("a" * 64 + ".example.com")
    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain("user@..invalid")
    assert SecurityGuard.normalize_domain("sub.EXAMPLE.com") == "sub.example.com"


# ==========================================
# 2. client.py, config.py & transport_security.py Edge Cases
# ==========================================


def test_client_lazy_httpx2_failures_auth_warnings_and_timeout_recovery(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
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

    with pytest.raises(ValueError, match="forbidden control characters or CRLF"):
        SecretAuth(("bad\x7fkey", "secret"))

    # SecureHTTPAdapter skips HTTPS-only isolation on plain http URLs (localhost loop test)
    adapter = SecureHTTPAdapter()
    conn = MagicMock(ssl_context="unchanged", ca_certs="orig", ca_cert_dir="orig_dir")
    adapter.cert_verify(conn, "http://localhost/v3/send", True, None)
    assert conn.ssl_context == "unchanged"

    # AsyncClient closed placeholder session (safe even with broken SSL_CERT_FILE), stale re-entry,
    # isolated request via MockTransport, and stream=True rejection
    if _httpx2 is not None:
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "nonexistent_conda_cacert.pem"))

        def _mock_transport_handler(request: Any) -> Any:
            return _httpx2.Response(200, json={"Data": []}, request=request)

        mock_tp = _httpx2.MockTransport(_mock_transport_handler)

        async def _check_async_edges() -> None:
            aclient = AsyncClient(auth=("pub", "priv"), transport=mock_tp)
            await aclient.aclose()
            closed_sess = aclient.session
            assert closed_sess.is_closed
            # Calling session again while already closed reuses closed placeholder when not yet disposed
            assert aclient.session is closed_sess

            stale_mock_sess = AsyncMock()
            stale_mock_sess.is_closed = False
            aclient._session = stale_mock_sess
            async with aclient as entered:
                stale_mock_sess.aclose.assert_awaited_once()
                assert entered is aclient

            with pytest.raises(ValueError, match="stream=True is not supported"):
                await entered.api_call("GET", "https://api.mailjet.com/v3/REST/contact", stream=True)

            # Isolated request branch when per-call proxies are supplied (mocked transport, zero network I/O)
            with patch.object(_httpx2, "AsyncHTTPTransport", return_value=mock_tp) as mock_http_tp:
                iso_resp = await entered._execute_request(
                    "GET",
                    "https://api.mailjet.com/v3/REST/contact",
                    {},
                    None,
                    None,
                    5,
                    proxies={"https": "https://localhost:8443"},
                )
            assert iso_resp.status_code == 200
            assert mock_http_tp.call_args.kwargs["proxy"] == "https://localhost:8443"

        asyncio.run(_check_async_edges())


# ==========================================
# 3. builders.py, filesystem_security.py, html_guard.py & routing.py Edge Cases
# ==========================================


def test_builders_filesystem_html_and_routing_edges(tmp_path: Path) -> None:
    """Cover ChunkedStreamer TOCTOU size guard, SpamGuard warnings, routing stacklevel, and dynamic routes."""
    big_file = tmp_path / "grew.bin"
    big_file.write_bytes(b"A" * 64)
    fake_stat = MagicMock(st_mode=0o100644, st_size=10)
    with patch("os.fstat", return_value=fake_stat):
        with pytest.raises(ValueError, match="exceeds safe threshold"):
            ChunkedStreamer.encode_file(big_file, chunk_size=12, safe_base_dir=tmp_path, max_bytes=20)

    # Second attach_file reuses existing Attachments list; missing content raises ValueError
    att1 = tmp_path / "a.txt"
    att2 = tmp_path / "b.txt"
    att1.write_text("one", encoding="utf-8")
    att2.write_text("two", encoding="utf-8")
    mb = (
        MessageBuilder()
        .set_sender("a@example.com")
        .add_recipient("b@example.com")
        .attach_file(att1, base_dir=tmp_path)
        .attach_file(att2, base_dir=tmp_path)
    )
    with pytest.raises(ValueError, match="TextPart, HTMLPart, or TemplateID is required"):
        mb.build()
    mb.set_tracking(opens="enabled", clicks=None)

    with patch.object(SecurityGuard, "analyze_html_safety", return_value={"is_safe": False, "issues": ["warn"]}):
        old_msg_flag = MessageBuilder.ENABLE_SPAM_GUARD
        old_tpl_flag = TemplateContentBuilder.ENABLE_SPAM_GUARD
        MessageBuilder.ENABLE_SPAM_GUARD = True
        TemplateContentBuilder.ENABLE_SPAM_GUARD = True
        try:
            with pytest.warns(UserWarning, match="Deliverability Warning"):
                MessageBuilder().set_content(html="<p>hello</p>")
            with pytest.warns(UserWarning, match="Deliverability Warning"):
                TemplateContentBuilder().set_content(html="<p>hello</p>")
        finally:
            MessageBuilder.ENABLE_SPAM_GUARD = old_msg_flag
            TemplateContentBuilder.ENABLE_SPAM_GUARD = old_tpl_flag

    spb = SendPayloadBuilder()
    spb._messages = [{"From": {"Email": "a@example.com"}, "To": [], "Subject": "s"}] * 51  # type: ignore[assignment]
    with pytest.raises(ValueError, match="at most 50 messages"):
        spb.build()

    # filesystem_security non-regular file and invalid multipart entries
    with pytest.raises(ValueError, match="not a regular file"):
        check_file_size(tmp_path)
    assert validate_attachment_path(os.fsencode(att1), safe_base_dir=tmp_path) == att1.resolve()  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Null byte"):
        validate_attachment_path(b"bad\x00path", safe_base_dir=tmp_path)  # type: ignore[arg-type]
    validate_multipart_files("not-a-mapping", header_sanitizer=dict)
    validate_multipart_files([("bad_arity",)], header_sanitizer=dict)
    validate_multipart_files({"f": "scalar-spec"}, header_sanitizer=dict)

    # html_guard handle_comment tag budget
    parser = build_spam_guard_parser()(max_tags=1)
    parser.feed("<!-- one -->")
    with pytest.raises(ValidationError, match="exceeds maximum tag limit"):
        parser.feed("<!-- two -->")

    # routing stacklevel & dynamic routes
    with patch("sys._getframe", side_effect=ValueError("no frame")):
        assert external_stacklevel() == 2

    fake_frame = types.SimpleNamespace(f_globals={"__name__": "mailjet_rest.sub"}, f_back=None)
    with patch("sys._getframe", return_value=fake_frame):
        assert external_stacklevel() == 2

    assert resolve_dynamic_route("send", "send", ["send"], "https://api.mailjet.com", "v3", None, None) == (
        "https://api.mailjet.com/v3/send",
        None,
        None,
    )
    assert resolve_dynamic_route(
        "batchjob_csvdata",
        "batchjob",
        ["batchjob", "csvdata"],
        "https://api.mailjet.com",
        "v3",
        None,
        "extra",
    ) == ("https://api.mailjet.com/v3/DATA/batchjob", None, "extra")
