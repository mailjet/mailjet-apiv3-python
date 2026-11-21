"""Mutation-killing contract tests for errors, retry, telemetry, and Client/AsyncClient."""

from __future__ import annotations

import asyncio
import copy
import importlib
import io
import logging
import warnings
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mailjet_rest.client import (
    AsyncClient,
    BaseClient,
    Client,
    _httpx2,
    logging_handler,
    parse_response,
)
from mailjet_rest.config import Config
from mailjet_rest.errors import (
    MAX_ERROR_BODY_CHARS,
    ApiError,
    CriticalApiError,
    MailjetApiError,
    TimeoutError as MailjetTimeoutError,
    _extract_json_error_message,
    extract_error_detail,
    raise_connection_error,
    raise_mapped_http_error,
)
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.retry import (
    RETRY_ALLOWED_METHODS,
    TRANSIENT_STATUS_CODES,
    reset_stream_pointers,
    run_async_with_retries,
    snapshot_stream_offsets,
)
from mailjet_rest.utils.telemetry import (
    _select_trace_mapping,
    extract_telemetry,
    log_api_response,
    record_debug_telemetry,
)


# ==========================================
# errors.py, retry.py & telemetry.py mutation contracts
# ==========================================


def test_errors_body_truncation_boundary_and_empty_list_json_shapes() -> None:
    """Verify exact MAX_ERROR_BODY_CHARS boundary and empty-list/non-dict JSON error shapes."""
    exact_body = "x" * MAX_ERROR_BODY_CHARS
    resp_exact = SimpleNamespace(status_code=500, text=exact_body, json=dict)
    with pytest.raises(MailjetApiError) as exc_exact:
        raise_mapped_http_error(resp_exact, RuntimeError("e500"))
    assert exc_exact.value.response_body == exact_body
    assert "...[truncated]" not in exc_exact.value.response_body

    over_body = exact_body + "y"
    resp_over = SimpleNamespace(status_code=500, text=over_body, json=dict)
    with pytest.raises(MailjetApiError) as exc_over:
        raise_mapped_http_error(resp_over, RuntimeError("e500"))
    assert exc_over.value.response_body == f"{exact_body}...[truncated]"

    assert _extract_json_error_message(SimpleNamespace(json=lambda: ["not-dict"])) == ""
    assert _extract_json_error_message(SimpleNamespace(json=lambda: {"Messages": []})) == ""
    assert _extract_json_error_message(SimpleNamespace(json=lambda: {"Messages": [{"Errors": []}]})) == ""
    assert extract_error_detail(SimpleNamespace(json=lambda: ["not-dict"]), "") == ""


def test_retry_stream_depth_offsets_and_exact_retry_attempt_count() -> None:
    """Verify exact stream recursion depth=4 boundary, non-zero offset rewind, and max_retries + 1 calls."""
    deep_4 = io.BytesIO(b"depth4")
    deep_4.seek(2)
    deep_5 = io.BytesIO(b"depth5")
    deep_5.seek(3)
    # Depth trace: data(0) -> list(1) -> list(2) -> list(3) -> deep_4(4) captured; list(4) -> deep_5(5) skipped
    nested = [[[[deep_4, [deep_5]]]]]
    captured = snapshot_stream_offsets(nested, None)
    assert captured == {id(deep_4): 2}

    # Stream raising OSError or returning bool from tell() must not crash or store bool
    bad_tell = SimpleNamespace(seek=lambda _p: None, seekable=lambda: True, closed=False, tell=lambda: True)
    oserr_tell = SimpleNamespace(
        seek=lambda _p: None,
        seekable=lambda: True,
        closed=False,
        tell=MagicMock(side_effect=OSError("bad tell")),
    )
    assert snapshot_stream_offsets([bad_tell, oserr_tell], None) == {}

    # Unrecorded stream falls back to 0 when offsets dict lacks id
    buf = io.BytesIO(b"0123456789")
    buf.seek(7)
    reset_stream_pointers(buf, None, offsets={})
    assert buf.tell() == 0

    # run_async_with_retries executes exact max_retries + 1 attempts and preserves non-zero data offset
    fake_httpx2 = SimpleNamespace(
        TimeoutException=type("T", (Exception,), {}),
        NetworkError=type("N", (Exception,), {}),
        RemoteProtocolError=type("R", (Exception,), {}),
        ProxyError=type("P", (Exception,), {}),
        UnsupportedProtocol=type("U", (Exception,), {}),
        DecodingError=type("D", (Exception,), {}),
    )
    retry_stream = io.BytesIO(b"abcdef")
    retry_stream.seek(2)
    seen_positions: list[int] = []

    async def _always_503() -> Any:
        seen_positions.append(retry_stream.tell())
        retry_stream.read(2)
        return SimpleNamespace(status_code=503, headers={"Retry-After": "0"}, is_closed=True)

    with patch("asyncio.sleep", AsyncMock()):
        final_resp = asyncio.run(
            run_async_with_retries(
                _always_503,
                fake_httpx2,
                method="GET",
                url="https://api.mailjet.com/v3/REST/contact",
                raw_retries=2,
                max_retries_limit=20,
                allowed_methods=RETRY_ALLOWED_METHODS,
                transient_status_codes=TRANSIENT_STATUS_CODES,
                max_delay=5.0,
                data=retry_stream,
                files=None,
                log=logging.getLogger("mailjet_rest.test.retry_count"),
            )
        )
    assert final_resp.status_code == 503
    assert seen_positions == [2, 2, 2]  # 1 initial + 2 retries, each restored to exact initial offset 2


def test_telemetry_multi_field_status_boundaries_and_debug_gate(caplog: pytest.LogCaptureFixture) -> None:
    """Verify telemetry extraction edge inputs, status_code=400 error log, and DEBUG status gate."""
    assert _select_trace_mapping({"Messages": []}) == {"Messages": []}
    assert _select_trace_mapping("invalid") is None
    trace_suffix, trace_attrs = extract_telemetry({"Messages": [{"CustomID": "c1", "TemplateID": "99"}]})
    assert trace_attrs == {"mailjet.customid": "c1", "mailjet.templateid": "99"}
    assert trace_suffix.startswith(" | Trace: [")
    assert trace_suffix.endswith("]")
    assert set(trace_suffix[len(" | Trace: [") : -1].split(" ")) == {"CustomID=c1", "TemplateID=99"}

    tlog = logging.getLogger("mailjet_rest.test.telemetry_contracts")
    caplog.clear()
    with caplog.at_level(logging.DEBUG, logger="mailjet_rest.test.telemetry_contracts"):
        log_api_response(
            tlog, "POST", "https://api.mailjet.com/v3/send", SimpleNamespace(status_code=400, text="bad"), " | T"
        )
        log_api_response(tlog, "GET", "https://api.mailjet.com/v3/contact", SimpleNamespace(status_code=0), "")
        record_debug_telemetry(
            tlog, "POST", "https://api.mailjet.com/v3/send", SimpleNamespace(status_code=500, text="err"), {}, None
        )
        record_debug_telemetry(
            tlog,
            "POST",
            "https://api.mailjet.com/v3/send",
            SimpleNamespace(status_code=201),
            {"TemplateID": "77"},
            None,
        )
        record_debug_telemetry(
            tlog, "DELETE", "https://api.mailjet.com/v3/send", SimpleNamespace(status_code=204), {}, None
        )

    error_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.ERROR]
    debug_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.DEBUG]
    assert error_msgs == ["API Error 400 | POST https://api.mailjet.com/v3/send | T | Response: bad"]
    assert debug_msgs == [
        "API Success 200 | GET https://api.mailjet.com/v3/contact",
        "API Success 201 | POST https://api.mailjet.com/v3/send | Trace: [TemplateID=77]",
        "API Success 204 | DELETE https://api.mailjet.com/v3/send",
    ]


# ==========================================
# client.py sync & async mutation contracts
# ==========================================


def test_sync_client_ping_redirects_proxy_idempotency_and_session_contracts(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify sync Client config session wiring, proxy lookup, redirect warnings, idempotency keys, and ping."""
    client_mod: Any = importlib.import_module("mailjet_rest.client")
    assert client_mod._resolve_proxy_url({"HTTP:": "http://proxy.example:8080"}) == "http://proxy.example:8080"
    assert client_mod._resolve_proxy_url({"http": "http://proxy2.example:8080"}) == "http://proxy2.example:8080"

    with warnings.catch_warnings(record=True) as no_auth_warn:
        warnings.simplefilter("always", UserWarning)
        with Client(auth=None) as anon_client:
            pass
    assert any("without 'auth' credentials" in str(w.message) for w in no_auth_warn)
    assert anon_client._closed is True

    # Custom max_retries (5) constructs non-default JitterRetry with exact settings
    with Client(
        auth=("k", "s"),
        config=Config(max_retries=5, pool_connections=15, pool_maxsize=25),
    ) as custom_client:
        adapter: Any = custom_client.session.get_adapter("https://api.mailjet.com")
        assert adapter.max_retries.total == 5
        assert adapter.max_retries.backoff_factor == 1
        assert adapter.max_retries.raise_on_status is False
        assert adapter._pool_connections == 15
        assert adapter._pool_maxsize == 25

        # Idempotency fingerprint changes if ANY of method, url, or data changes
        h_post_a: dict[str, str | None] = {}
        h_post_b: dict[str, str | None] = {}
        h_put_a: dict[str, str | None] = {}
        h_other_url: dict[str, str | None] = {}
        custom_client._apply_idempotency({"x": 1}, h_post_a, method="post", url="https://api.mailjet.com/v3/REST/a")
        custom_client._apply_idempotency({"x": 1}, h_post_b, method="POST", url="https://api.mailjet.com/v3/REST/a")
        custom_client._apply_idempotency({"x": 1}, h_put_a, method="PUT", url="https://api.mailjet.com/v3/REST/a")
        custom_client._apply_idempotency({"x": 1}, h_other_url, method="POST", url="https://api.mailjet.com/v3/REST/b")
        assert h_post_a["Idempotency-Key"] == h_post_b["Idempotency-Key"]
        assert h_post_a["Idempotency-Key"] != h_put_a["Idempotency-Key"]
        assert h_post_a["Idempotency-Key"] != h_other_url["Idempotency-Key"]

        # dry_run returns utf-8 JSON response and emits INFO log
        custom_client.config.dry_run = True
        caplog.clear()
        with caplog.at_level(logging.INFO, logger="mailjet_rest.client"):
            dry_res = custom_client.api_call("POST", "https://api.mailjet.com/v3.1/send", data={"Messages": []})
        assert dry_res.encoding == "utf-8"
        assert dry_res.headers["Content-Type"] == "application/json"
        assert any("DRY RUN: Intercepted POST request" in rec.getMessage() for rec in caplog.records)

        # Redirect status boundaries: 300 warns, 304 ignored, 400 ignored
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="mailjet_rest.client"):
            BaseClient._check_unexpected_redirect("https://api.mailjet.com/u", SimpleNamespace(status_code=300))
            BaseClient._check_unexpected_redirect("https://api.mailjet.com/u", SimpleNamespace(status_code=304))
            BaseClient._check_unexpected_redirect("https://api.mailjet.com/u", SimpleNamespace(status_code=400))
        warn_msgs = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert len(warn_msgs) == 1
        assert "300" in warn_msgs[0]

        # deepcopy clone preserves auth cleanly
        cloned = copy.deepcopy(custom_client)
        assert cloned.auth == custom_client.auth
        cloned.close()

        # Exact ping boundary: 399 -> True, 400 -> False
        with patch.object(Client, "api_call", return_value=SimpleNamespace(status_code=399)) as mock_ping_ok:
            assert custom_client.ping(timeout=4.5) is True
        mock_ping_ok.assert_called_once_with(
            "GET", "https://api.mailjet.com/v3/REST/apikey", filters={"Limit": 1}, timeout=4.5
        )

        with patch.object(Client, "api_call", side_effect=ApiError("down")):
            assert custom_client.ping() is False

    # Deprecated functions exact warning wording + connection error message
    with pytest.warns(DeprecationWarning, match=r"^parse_response is deprecated\.$"):
        assert parse_response(SimpleNamespace(json=lambda: {"ok": 1})) == {"ok": 1}  # type: ignore[arg-type]
    with pytest.warns(DeprecationWarning, match=r"^logging_handler is deprecated\.$"):
        logging_handler(None)
    with pytest.raises(CriticalApiError, match="Connection to Mailjet API failed: boom"):
        raise_connection_error(RuntimeError("boom"))


def test_async_client_dry_run_ping_isolated_and_streaming_content_contracts() -> None:
    """Verify AsyncClient dry_run response, ping boundary, isolated transport forwarding, and StringIO read."""
    if _httpx2 is None:
        pytest.skip("httpx2 optional extra not installed")
    httpx2_mod = _httpx2
    assert httpx2_mod is not None

    async def _exercise() -> None:
        async with AsyncClient(auth=("pub", "priv"), config=Config(dry_run=True)) as ac:
            dry = await ac.api_call("post", "https://api.mailjet.com/v3.1/send", data={"Messages": []})  # type: ignore[arg-type]
            assert dry.status_code == 200
            assert dry.headers["Content-Type"] == "application/json"
            assert dry.request.method == "POST"

            with patch.object(
                AsyncClient, "api_call", AsyncMock(return_value=SimpleNamespace(status_code=399))
            ) as m_ok:
                assert await ac.ping(timeout=6.0) is True
            m_ok.assert_awaited_once_with(
                "GET", "https://api.mailjet.com/v3/REST/apikey", filters={"Limit": 1}, timeout=6.0
            )

            with patch.object(AsyncClient, "api_call", AsyncMock(return_value=SimpleNamespace(status_code=400))):
                assert await ac.ping() is False

            ac.config.dry_run = False
            with pytest.raises(ValueError, match="stream=True is not supported"):
                await ac._execute_request(
                    "GET", "https://api.mailjet.com/v3/REST/contact", {}, None, None, 5.0, stream=True
                )

            # _execute_request encodes string stream chunks as UTF-8 and isolates custom cert requests
            sent_reqs: list[tuple[Any, dict[str, Any]]] = []

            async def _handler(req: Any) -> Any:
                sent_reqs.append((req, {"content": req.content}))
                return httpx2_mod.Response(200, json={"Data": []})

            mock_transport = httpx2_mod.MockTransport(_handler)
            with (
                patch("mailjet_rest.client.SecurityGuard.check_request_security"),
                patch.object(AsyncClient, "_build_transport", return_value=mock_transport) as mock_build_tp,
            ):
                resp = await ac._execute_request(
                    "POST",
                    "https://api.mailjet.com/v3/REST/contact",
                    {"Content-Type": "text/plain"},
                    io.StringIO("héllo"),
                    None,
                    5.0,
                    cert=("client.pem", "client.key"),
                    verify=True,
                )
            assert resp.status_code == 200
            assert sent_reqs[0][1]["content"] == "héllo".encode()
            assert mock_build_tp.call_args.kwargs["cert"] == ("client.pem", "client.key")

            with patch.object(AsyncClient, "_execute_request", AsyncMock(side_effect=httpx2_mod.ReadTimeout("slow"))):
                with pytest.raises(MailjetTimeoutError):
                    await ac.api_call("GET", "https://api.mailjet.com/v3/REST/contact")

    asyncio.run(_exercise())
    assert SecurityGuard._has_forbidden_header_chars("ok") is False
    assert SecurityGuard._has_forbidden_header_chars("bad\rheader") is True
