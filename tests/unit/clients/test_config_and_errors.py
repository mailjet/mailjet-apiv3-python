# pyright: reportOperatorIssue=false
# pyright: reportReturnType=false
"""Unit tests for Mailjet SDK Config validation, retry/backoff, telemetry, and error mapping."""

from __future__ import annotations

import asyncio
import email.utils
import io
import logging
import warnings
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]

from mailjet_rest.client import BaseClient, Client, Config, logging_handler, parse_response
from mailjet_rest.errors import (
    ActionDeniedError,
    ApiError,
    ApiRateLimitError,
    AuthorizationError,
    DoesNotExistError,
    MailjetApiError,
    TimeoutError as MailjetTimeoutError,
    ValidationError,
    extract_error_detail,
    handle_api_error,
    raise_mapped_http_error,
    raise_timeout_error,
    sanitize_error_text,
)
from mailjet_rest.types import _JSON_HEADERS, _TEXT_HEADERS
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.retry import (
    DEFAULT_RETRY_STRATEGY,
    JitterRetry,
    _check_async_retry_response,
    compute_retry_delay,
    parse_retry_after_http_date,
    reset_stream_pointers,
    run_async_with_retries,
)
from mailjet_rest.utils.telemetry import record_debug_telemetry


# ==========================================
# 1. Config Validation & Header Immutability
# ==========================================


def test_config_api_url_validation_scheme() -> None:
    """Verify that insecure or unsupported URL schemes are immediately rejected (CWE-319 / CWE-918)."""
    with pytest.raises(ValueError, match="Security Alert \\(CWE-319\\): Unencrypted 'http://'"):
        Config(api_url="http://api.mailjet.com")
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


def test_infinite_timeout_resource_exhaustion() -> None:
    """Coverage: Checks the float validation logic directly on the Config object (CWE-400)."""
    with pytest.raises(ValueError, match="Timeout cannot be Infinity or NaN"):
        Config(timeout=float("inf"))


def test_zero_timeout_resource_exhaustion() -> None:
    """Coverage: Checks that 0 or negative timeouts are blocked."""
    with pytest.raises(ValueError, match="strictly positive"):
        Config(timeout=0)


def test_config_api_url_missing_slash() -> None:
    """Coverage: Ensure Config adds trailing slash to api_url."""
    c = Config(api_url="https://api.mailjet.com")
    assert c.api_url == "https://api.mailjet.com/"


def test_user_agent() -> None:
    client = Client(auth=("test", "test"))
    assert "mailjet-apiv3-python" in client.session.headers["User-Agent"]


def test_header_constants_immutability(client_offline: Client) -> None:
    """Verify that global header mappings are strictly immutable."""
    with pytest.raises(TypeError):
        _JSON_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]

    with pytest.raises(TypeError):
        _TEXT_HEADERS["Content-Type"] = "hacked"  # type: ignore[index]


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


def test_config_max_retries_validation() -> None:
    """Verify Config.max_retries accepts integers >= 0 and rejects booleans, negatives, and non-ints."""
    assert Config().max_retries == 3
    assert Config(max_retries=0).max_retries == 0
    assert Config(max_retries=5).max_retries == 5

    bad_values: tuple[Any, ...] = (-1, True, False, "2", 1.5)
    for bad_val in bad_values:
        with pytest.raises(ValueError, match="max_retries"):
            Config(max_retries=bad_val)


def test_config_pool_and_warn_unclosed_validation() -> None:
    """Config validates pool_connections, pool_maxsize, and warn_unclosed strictly."""
    with pytest.raises(ValueError, match="pool_connections"):
        Config(pool_connections=0)
    with pytest.raises(ValueError, match="pool_maxsize"):
        Config(pool_maxsize=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="warn_unclosed"):
        Config(warn_unclosed="yes")  # type: ignore[arg-type]


def test_config_validation_exact_messages_and_minimum_bounds() -> None:
    """Kill surviving mutants in mailjet_rest.config.Config."""
    cfg_min = Config(pool_connections=1, pool_maxsize=1, max_retries=0)
    assert cfg_min.pool_connections == 1
    assert cfg_min.pool_maxsize == 1
    assert cfg_min.max_retries == 0

    with pytest.raises(ValueError, match=r"^pool_connections must be an integer >= 1, got 0\.$"):
        Config(pool_connections=0)
    with pytest.raises(ValueError, match=r"^pool_maxsize must be an integer >= 1, got 0\.$"):
        Config(pool_maxsize=0)
    with pytest.raises(ValueError, match=r"^max_retries must be an integer >= 0, got -1\.$"):
        Config(max_retries=-1)

    class _CustomDomainConfig(Config):
        ALLOWED_ROOT_DOMAIN = "custom.example"

    cfg_custom = _CustomDomainConfig(api_url="https://api.custom.example/")
    assert cfg_custom.api_url == "https://api.custom.example/"

    with pytest.raises(ValueError, match="is not permitted"):
        Config(api_url="https://evil.example.com")
    with pytest.raises(TypeError) as exc_warn:
        Config(warn_unclosed="yes")  # type: ignore[arg-type]
    assert str(exc_warn.value) == "warn_unclosed must be a bool, got str."


# ==========================================
# 2. Legacy Deprecations, Errors & Telemetry
# ==========================================


def test_legacy_exceptions_exist_and_inherit_properly() -> None:
    """Verify that all deprecated exceptions were restored and inherit from Exception."""
    for error_class in [
        AuthorizationError,
        ActionDeniedError,
        DoesNotExistError,
        ValidationError,
        ApiRateLimitError,
    ]:
        assert issubclass(error_class, Exception)
        # Even though they aren't actively raised by the SDK anymore,
        # checking initialization ensures users' try/except blocks won't crash.
        instance = error_class("Legacy Error")
        assert str(instance) == "Legacy Error"


def test_parse_response_emits_deprecation_warning() -> None:
    """Verify parse_response gracefully falls back to JSON/Text while warning the developer."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b'{"success": true}'

    with pytest.warns(DeprecationWarning, match="parse_response is deprecated"):
        result = parse_response(resp)
        assert isinstance(result, dict)


def test_parse_response_handles_value_error_fallback() -> None:
    """Verify text fallback on invalid JSON payloads."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"invalid json"

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        result = parse_response(resp)
        assert result == "invalid json"


def test_logging_handler_emits_deprecation_warning() -> None:
    """Verify the old standalone handler is marked for removal."""
    with pytest.warns(DeprecationWarning, match="logging_handler is deprecated"):
        logging_handler(None)


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


def test_errors_exact_extraction_truncation_and_defaults() -> None:
    """Kill surviving mutants in mailjet_rest.errors."""
    default_err = MailjetApiError("boom")
    assert default_err.status_code == 0
    assert default_err.response_body == ""

    assert sanitize_error_text("", max_chars=5) == ""
    assert sanitize_error_text(None, max_chars=5) == ""
    assert sanitize_error_text("abcde", max_chars=5) == "abcde"
    assert sanitize_error_text("abcdef", max_chars=5) == "abcde...[truncated]"

    resp_top = MagicMock()
    resp_top.json.return_value = {"ErrorMessage": "top level error"}
    assert extract_error_detail(resp_top, "") == ": top level error"

    bad_payloads: tuple[dict[str, Any], ...] = (
        {"Messages": "not-list"},
        {"Messages": [{"Errors": "not-list"}]},
        {"Messages": [{"Errors": [{}]}]},
    )
    for bad_payload in bad_payloads:
        resp_bad = MagicMock()
        resp_bad.json.return_value = bad_payload
        assert extract_error_detail(resp_bad, "") == ""

    resp_non_json = MagicMock()
    resp_non_json.json.side_effect = ValueError("bad json")
    assert extract_error_detail(resp_non_json, "gateway down") == ": gateway down"
    assert extract_error_detail(resp_non_json, "") == ""

    bare_resp = SimpleNamespace(
        status_code=500,
        json=lambda: (_ for _ in ()).throw(ValueError("not json")),
    )
    with pytest.raises(MailjetApiError) as exc_bare:
        raise_mapped_http_error(bare_resp, RuntimeError("server 500"))
    assert str(exc_bare.value) == "Mailjet API HTTP 500"
    assert exc_bare.value.response_body == ""


# ==========================================
# 3. Retry, Backoff & Log Sanitization
# ==========================================


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


def test_retry_budget_ceiling_http_date_and_error_log_sanitization(caplog: pytest.LogCaptureFixture) -> None:
    """CAND-INV-44/45/48/54/56: Enforce max_retries ceiling, HTTP-date Retry-After cap, and sanitized error logs."""
    assert Config.MAX_RETRIES_LIMIT == 20
    assert Config(max_retries=20).max_retries == 20
    with pytest.raises(ValueError, match="max_retries"):
        Config(max_retries=21)

    future_dt = datetime.now(timezone.utc) + timedelta(seconds=300)
    past_dt = datetime.now(timezone.utc) - timedelta(seconds=60)
    assert BaseClient._compute_retry_delay(0, email.utils.format_datetime(future_dt)) == 60.0
    assert BaseClient._compute_retry_delay(0, email.utils.format_datetime(past_dt)) == 0.0

    # Oversized and control-char-forged response bodies are neutralized and truncated
    fake_resp = MagicMock()
    fake_resp.status_code = 502
    fake_resp.text = "bad\r\nFAKE LOG ENTRY\x00" + ("A" * 3000)
    fake_resp.json.return_value = {"ErrorMessage": "line1\r\nforged\x00" + ("B" * 1500)}

    detail = BaseClient._extract_error_detail(fake_resp, fake_resp.text)
    assert "\r" not in detail
    assert "\n" not in detail
    assert "\x00" not in detail
    assert "...[truncated]" in detail
    assert len(detail) <= BaseClient._MAX_ERROR_DETAIL_CHARS + 32

    with caplog.at_level(logging.ERROR):
        BaseClient._log_request("POST", "https://api.mailjet.com/v3.1/send", fake_resp, "")
    err_logs = [rec.message for rec in caplog.records if rec.levelno == logging.ERROR]
    assert err_logs
    assert "\r" not in err_logs[-1]
    assert "\n" not in err_logs[-1]
    assert "\x00" not in err_logs[-1]
    assert "...[truncated]" in err_logs[-1]


def test_compute_retry_delay_bounds_and_http_date_max_delay() -> None:
    """Kill survived mutants in compute_retry_delay exponentiation and uniform bounds."""
    future_dt = datetime.now(timezone.utc) + timedelta(seconds=30)
    http_date = email.utils.format_datetime(future_dt)
    assert compute_retry_delay(0, retry_after_header=http_date, max_delay=5.0) == 5.0

    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=0.5) as mock_uniform:
        assert compute_retry_delay(0, max_delay=60.0) == 0.5
    assert mock_uniform.call_args.args == (0.0, 1.0)

    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=1.5) as mock_uniform2:
        assert compute_retry_delay(2, max_delay=100.0) == 1.5
    assert mock_uniform2.call_args.args == (0.0, 4.0)


def test_retry_jitter_stream_pointers_and_async_retries_mutants() -> None:
    """Kill survived mutants in JitterRetry.get_backoff_time, stream pointer resets, and async retries."""
    # JitterRetry.get_backoff_time: 0 when no retries taken, uniform(0, base) when history >= 2
    zero_retry = JitterRetry(total=3, backoff_factor=1.0)
    assert zero_retry.get_backoff_time() == 0

    after_retries = zero_retry.increment(method="GET", url="https://api.mailjet.com").increment(
        method="GET", url="https://api.mailjet.com"
    )
    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=0.75) as mock_uniform:
        val = after_retries.get_backoff_time()
    assert val == 0.75
    mock_uniform.assert_called_once()
    low, high = mock_uniform.call_args.args
    assert low == 0
    assert high > 0

    # Retry: raise_on_status=False, zero backoff skips SystemRandom.uniform, stream reset depth 4 vs 5, OSError/ValueError
    assert DEFAULT_RETRY_STRATEGY.raise_on_status is False
    jr0 = (
        JitterRetry(total=3, backoff_factor=0.0)
        .increment(method="GET", url="https://api.mailjet.com")
        .increment(method="GET", url="https://api.mailjet.com")
    )
    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform") as mock_uni:
        assert jr0.get_backoff_time() == 0
        mock_uni.assert_not_called()

    buf_d4_data = io.BytesIO(b"data4")
    buf_d4_data.read()
    buf_d4_files = io.BytesIO(b"files4")
    buf_d4_files.read()
    buf_d5 = io.BytesIO(b"depth5")
    buf_d5.read()
    closed_buf = io.BytesIO(b"closed")
    closed_buf.close()

    class _NoClosedStream:
        def seekable(self) -> bool:
            return True

        def seek(self, pos: int) -> None:
            self.pos = pos

    class _ErrStream:
        def __init__(self, exc_type: type[Exception]) -> None:
            self.exc_type = exc_type

        def seek(self, _pos: int) -> None:
            raise self.exc_type("cannot seek")

    no_closed = _NoClosedStream()
    reset_stream_pointers(
        [[[[buf_d4_data]]], [[[[[buf_d5]]]]], closed_buf, no_closed],
        [[[[buf_d4_files]]], _ErrStream(OSError), _ErrStream(ValueError)],
    )
    assert buf_d4_data.tell() == 0
    assert buf_d4_files.tell() == 0
    assert buf_d5.tell() == 6  # depth > 4 skipped
    assert getattr(no_closed, "pos") == 0

    # run_async_with_retries negative retries & non-retryable method
    fake_httpx2 = SimpleNamespace(
        TimeoutException=type("T", (Exception,), {}),
        NetworkError=type("N", (Exception,), {}),
        RemoteProtocolError=type("R", (Exception,), {}),
        ProxyError=type("P", (Exception,), {}),
        UnsupportedProtocol=type("U", (Exception,), {}),
        DecodingError=type("D", (Exception,), {}),
    )
    with pytest.raises(ValueError, match="non-negative integer"):
        asyncio.run(
            run_async_with_retries(
                AsyncMock(),
                fake_httpx2,
                method="GET",
                url="https://api.mailjet.com",
                raw_retries=-1,
                max_retries_limit=20,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({503}),
                max_delay=60.0,
                data=None,
                files=None,
                log=logging.getLogger("test"),
            )
        )


def test_errors_and_retry_details_mutants(caplog: pytest.LogCaptureFixture) -> None:
    """Kill remaining non-equivalent mutants in errors.py and utils/retry.py."""
    # errors.py exact max_chars forwarding and timeout logger formatting
    long_resp = MagicMock(status_code=502, text="0123456789")
    long_resp.json.side_effect = ValueError("not json")
    exc_wrapper = RuntimeError("bad gateway")
    exc_wrapper.response = long_resp  # type: ignore[attr-defined]
    with pytest.raises(MailjetApiError) as exc_502:
        handle_api_error(exc_wrapper, max_chars=5)
    assert str(exc_502.value) == "Mailjet API HTTP 502: 01234...[truncated]"
    assert exc_502.value.status_code == 502
    assert exc_502.value.response_body == "0123456789"

    mapped_400 = MagicMock(status_code=400, text="badpayload_long")
    mapped_400.json.side_effect = ValueError("not json")
    with pytest.raises(MailjetApiError) as exc_400:
        raise_mapped_http_error(mapped_400, RuntimeError("400"), max_chars=4)
    assert str(exc_400.value) == "Payload validation failed: badp...[truncated]"
    assert exc_400.value.status_code == 400
    assert exc_400.value.response_body == "badpayload_long"

    err_log = logging.getLogger("mailjet_rest.test.timeout")
    with caplog.at_level(logging.ERROR, logger="mailjet_rest.test.timeout"):
        with pytest.raises(MailjetTimeoutError, match="Request to Mailjet API timed out: timed out"):
            raise_timeout_error(err_log, "POST", "https://api.mailjet.com/v3/send", RuntimeError("timed out"))
    assert len(caplog.records) == 1
    assert caplog.records[0].getMessage() == "Timeout Error: POST https://api.mailjet.com/v3/send"
    assert caplog.records[0].exc_info is not None

    # utils/retry.py JitterRetry (0 < backoff <= 1), bounded_exponent 20 vs 21, and run_async_with_retries logging/rewind
    jr_small = (
        JitterRetry(total=3, backoff_factor=0.25)
        .increment(method="GET", url="https://api.mailjet.com")
        .increment(method="GET", url="https://api.mailjet.com")
    )
    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=0.125) as mock_u_small:
        assert jr_small.get_backoff_time() == 0.125
    assert mock_u_small.call_args.args == (0, 0.5)

    with patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=1.0) as mock_u_exp:
        assert compute_retry_delay(21, max_delay=1e9) == 1.0
    assert mock_u_exp.call_args.args == (0.0, float(2**20))

    class _TExc(Exception):
        pass

    class _NExc(Exception):
        pass

    class _RExc(Exception):
        pass

    class _PExc(Exception):
        pass

    class _UExc(Exception):
        pass

    class _DExc(Exception):
        pass

    fake_httpx2 = SimpleNamespace(
        TimeoutException=_TExc,
        NetworkError=_NExc,
        RemoteProtocolError=_RExc,
        ProxyError=_PExc,
        UnsupportedProtocol=_UExc,
        DecodingError=_DExc,
    )

    with pytest.raises(ValueError, match="non-negative integer"):
        asyncio.run(
            run_async_with_retries(
                AsyncMock(),
                fake_httpx2,
                method="GET",
                url="https://api.mailjet.com/u",
                raw_retries=True,
                max_retries_limit=20,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({429}),
                max_delay=5.0,
                data=None,
                files=None,
                log=logging.getLogger("test"),
            )
        )

    retry_buf = io.BytesIO(b"retry-body")
    attempts: list[int] = []
    retry_log = logging.getLogger("mailjet_rest.test.retry")

    async def _send_sequence() -> Any:
        idx = len(attempts)
        attempts.append(retry_buf.tell())
        retry_buf.read()
        if idx == 0:
            raise _TExc("timeout 1")
        if idx == 1:
            resp_429 = MagicMock(status_code=429, headers={"retry-after": "12"}, is_closed=False)
            resp_429.aclose = AsyncMock(side_effect=RuntimeError("ignore close err"))
            return resp_429
        return SimpleNamespace(status_code=200, headers={})

    async def _run_seq() -> Any:
        with patch("asyncio.sleep", AsyncMock()) as mock_sleep:
            out = await run_async_with_retries(
                _send_sequence,
                fake_httpx2,
                method="POST",
                url="https://api.mailjet.com/u",
                raw_retries=3,
                max_retries_limit=20,
                allowed_methods=("POST",),
                transient_status_codes=frozenset({429}),
                max_delay=5.0,
                data=retry_buf,
                files=None,
                log=retry_log,
            )
        return out, mock_sleep

    caplog.clear()
    with (
        caplog.at_level(logging.WARNING, logger="mailjet_rest.test.retry"),
        patch("mailjet_rest.utils.retry.secrets.SystemRandom.uniform", return_value=0.5) as mock_u_async,
    ):
        seq_resp, sleep_mock = asyncio.run(_run_seq())

    assert seq_resp.status_code == 200
    assert attempts == [0, 0, 0]  # Stream pointer was rewound after every failed/transient attempt
    assert mock_u_async.call_args.args == (0.0, 1.0)
    assert [c.args[0] for c in sleep_mock.await_args_list] == [0.5, 5.0]
    msgs = [rec.getMessage() for rec in caplog.records]
    assert msgs == [
        "Transient async transport error (_TExc) on POST https://api.mailjet.com/u; retry 1/3 in 0.50s",
        "Transient HTTP 429 on POST https://api.mailjet.com/u; retry 2/3 in 5.00s",
    ]

    # When response lacks is_closed attribute, _check_async_retry_response must NOT call aclose()
    no_closed_attr_resp = SimpleNamespace(status_code=429, headers={}, aclose=AsyncMock())
    seq2 = iter([no_closed_attr_resp, SimpleNamespace(status_code=200)])

    async def _send_iter() -> Any:
        return next(seq2)

    with patch("asyncio.sleep", AsyncMock()):
        asyncio.run(
            run_async_with_retries(
                _send_iter,
                fake_httpx2,
                method="GET",
                url="https://api.mailjet.com/u",
                raw_retries=1,
                max_retries_limit=20,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({429}),
                max_delay=5.0,
                data=None,
                files=None,
                log=retry_log,
            )
        )
    no_closed_attr_resp.aclose.assert_not_awaited()
