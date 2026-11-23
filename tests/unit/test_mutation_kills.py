"""Targeted unit tests killing survived and untested mutants across core modules."""

from __future__ import annotations

import asyncio
import email.utils
import hashlib
import hmac
import io
import logging
import ssl
import types
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mailjet_rest.builders import MessageBuilder
from mailjet_rest.config import Config
from mailjet_rest.endpoint import AsyncEndpoint, BaseEndpoint, Endpoint
from mailjet_rest.errors import (
    MailjetApiError,
    TimeoutError as MailjetTimeoutError,
    extract_error_detail,
    handle_api_error,
    raise_mapped_http_error,
    raise_timeout_error,
    sanitize_error_text,
)
from mailjet_rest.testing import MockMailjetClient, MockResponse
from mailjet_rest.utils.retry import (
    DEFAULT_RETRY_STRATEGY,
    JitterRetry,
    compute_retry_delay,
    reset_stream_pointers,
    run_async_with_retries,
)
from mailjet_rest.utils.routing import (
    build_endpoint_url,
    cast_query_param,
    emit_deprecation_if_needed,
    external_stacklevel,
    normalize_stream_filters,
    split_endpoint_parts,
)
from mailjet_rest.utils.transport_security import _new_secure_ssl_context, coerce_httpx2_timeout
from mailjet_rest.utils.version import get_version, parse_semver_triplet
from mailjet_rest.webhooks import verify_webhook_signature


def test_base_endpoint_route_helpers_and_jitter_backoff_cover_untested_mutants() -> None:
    """Cover BaseEndpoint._resolve_registry_route, _resolve_dynamic_route, and JitterRetry.get_backoff_time."""
    client = MagicMock()
    base = BaseEndpoint(client, "contact_getcontactslists")

    url, res_id, act_id = base._resolve_registry_route("https://api.mailjet.com", "v3", 42, 7)
    assert url == "https://api.mailjet.com/v3/REST/contact/42/getcontactslists"
    assert res_id is None
    assert act_id == 7

    dyn = BaseEndpoint(client, "contactslist_csvdata")
    d_url, d_id, d_act = dyn._resolve_dynamic_route("https://api.mailjet.com", "v3", 10, "raw")
    assert d_url == "https://api.mailjet.com/v3/DATA/contactslist/10/CSVData/text:plain"
    assert d_id is None
    assert d_act == "raw"

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


def test_version_helpers_exact_validation_and_formatting() -> None:
    """Kill survived mutants in parse_semver_triplet and get_version."""
    assert parse_semver_triplet("1.9.2") == (1, 9, 2)
    with pytest.raises(ValueError, match="Expected X.Y.Z version string"):
        parse_semver_triplet("abc.1.2")

    assert get_version((1, 2, 3)) == "1.2.3"
    with pytest.raises(ValueError, match=r"^The tuple 'version' must contain 3 items$"):
        get_version((1, 2))  # type: ignore[arg-type]


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


def test_message_builder_set_template_defaults_and_error_messages() -> None:
    """Kill survived mutants in MessageBuilder.set_template."""
    mb = MessageBuilder().set_sender("a@example.com").add_recipient("b@example.com").set_template(1)
    built = mb.build()
    assert built.get("TemplateID") == 1
    assert built.get("TemplateLanguage") is True

    with pytest.raises(ValueError, match="template_id must be a strictly positive integer, got 0"):
        MessageBuilder().set_template(0)

    with pytest.raises(TypeError, match="language_active must be a bool, got str"):
        MessageBuilder().set_template(1, "yes")  # type: ignore[arg-type]


def test_endpoint_and_async_endpoint_patch_forward_all_args() -> None:
    """Kill survived argument-forwarding mutants in Endpoint.patch and AsyncEndpoint.patch."""
    sync_client = MagicMock()
    sync_client.config.api_url = "https://api.mailjet.com"
    sync_client.config.version = "v3"
    ep = Endpoint(sync_client, "contact")

    with pytest.warns(DeprecationWarning, match="deprecated"):
        ep.patch(
            id=7,
            data={"Name": "Patched"},
            action_id="sub",
            headers={"X-Test": "1"},
            ensure_ascii=False,
            data_encoding="utf-8",
            timeout=5,
        )
    sync_client.api_call.assert_called_once()
    call_kw = sync_client.api_call.call_args.kwargs
    assert call_kw["method"] == "PATCH"
    assert "/v3/REST/contact/7/sub" in call_kw["url"]
    assert call_kw["headers"]["X-Test"] == "1"
    assert call_kw["timeout"] == 5

    async def _run_async() -> None:
        async_client = MagicMock()
        async_client.config.api_url = "https://api.mailjet.com"
        async_client.config.version = "v3"
        sentinel = MagicMock()
        async_client.api_call = AsyncMock(return_value=sentinel)
        aep = AsyncEndpoint(async_client, "contact")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            res = await aep.patch(
                id=9,
                data={"Name": "AsyncPatched"},
                action_id="act",
                headers={"X-Async": "2"},
                ensure_ascii=False,
                data_encoding="utf-8",
                timeout=9,
            )
        assert res is sentinel
        async_client.api_call.assert_awaited_once()
        a_kw = async_client.api_call.call_args.kwargs
        assert a_kw["method"] == "PATCH"
        assert "/v3/REST/contact/9/act" in a_kw["url"]
        assert a_kw["headers"]["X-Async"] == "2"
        assert a_kw["timeout"] == 9

    asyncio.run(_run_async())


def test_async_endpoint_stream_max_items_and_kwargs_forwarding() -> None:
    """Kill survived mutants in AsyncEndpoint.stream pagination boundaries."""
    pages: list[dict[str, Any]] = [
        {"Data": [{"ID": 1}, {"ID": 2}]},
        {"Data": [{"ID": 3}, {"ID": 4}]},
    ]
    captured_filters: list[dict[str, Any]] = []

    async def _fake_api_call(*, filters: dict[str, Any] | None = None, **_kwargs: Any) -> MagicMock:
        captured_filters.append(dict(filters or {}))
        resp = MagicMock()
        resp.status_code = 200
        resp.text = "{}"
        resp.json.return_value = pages[len(captured_filters) - 1]
        return resp

    async def _run() -> list[dict[str, Any]]:
        async_client = MagicMock()
        async_client.config.api_url = "https://api.mailjet.com"
        async_client.config.version = "v3"
        async_client.api_call = AsyncMock(side_effect=_fake_api_call)
        aep = AsyncEndpoint(async_client, "contact")
        return [item async for item in aep.stream(chunk_size=2, max_items=3)]

    items = asyncio.run(_run())
    assert items == [{"ID": 1}, {"ID": 2}, {"ID": 3}]
    assert captured_filters == [{"Limit": 2, "Offset": 0}, {"Limit": 1, "Offset": 2}]


def _sign_hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def test_webhooks_exact_boundaries_defaults_and_error_messages() -> None:
    """Kill surviving mutants in mailjet_rest.webhooks.verify_webhook_signature."""
    payload = b'{"event":"open"}'
    secret = "whsec_mut_test"  # pragma: allowlist secret
    sig = _sign_hex(secret, payload)

    with patch("mailjet_rest.webhooks.time.time", return_value=1000.0):
        # Default max_age_seconds=300: delta == 300 passes, delta == 301 fails
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=700) is True
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=699) is False
        # max_age_seconds=0: delta == 0 passes, delta == 1 fails
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=1000, max_age_seconds=0) is True
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=999, max_age_seconds=0) is False

    with pytest.raises(TypeError) as e_payload:
        verify_webhook_signature("not-bytes", sig, secret)  # type: ignore[arg-type]
    assert str(e_payload.value) == "payload_bytes must be bytes, got str."

    with pytest.raises(TypeError) as e_sig:
        verify_webhook_signature(payload, 123, secret)  # type: ignore[arg-type]
    assert str(e_sig.value) == "signature_header must be str, got int."

    with pytest.raises(TypeError) as e_secret:
        verify_webhook_signature(payload, sig, 123)  # type: ignore[arg-type]
    assert str(e_secret.value) == "webhook_secret must be str, got int."

    with pytest.raises(ValueError) as e_age:
        verify_webhook_signature(payload, sig, secret, max_age_seconds=-1)
    assert str(e_age.value) == "max_age_seconds must be a non-negative integer."

    with pytest.raises(TypeError) as e_ts:
        verify_webhook_signature(payload, sig, secret, timestamp_unix="1000")  # type: ignore[arg-type]
    assert str(e_ts.value) == "timestamp_unix must be int or None, got str."


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

    bare_resp = types.SimpleNamespace(
        status_code=500,
        json=lambda: (_ for _ in ()).throw(ValueError("not json")),
    )
    with pytest.raises(MailjetApiError) as exc_bare:
        raise_mapped_http_error(bare_resp, RuntimeError("server 500"))
    assert str(exc_bare.value) == "Mailjet API HTTP 500"
    assert exc_bare.value.response_body == ""


def test_testing_module_mock_client_endpoint_and_response_contracts() -> None:
    """Kill surviving mutants in mailjet_rest.testing."""
    default_resp = MockResponse()
    assert default_resp.status_code == 200
    assert default_resp.text == ""
    assert default_resp.json() == {"Count": 0, "Total": 0, "Data": []}

    err_resp = MockResponse(status_code=503, text="down")
    with pytest.raises(MailjetApiError) as exc_mock:
        err_resp.raise_for_status()
    assert isinstance(exc_mock.value.__cause__, RuntimeError)
    assert str(exc_mock.value.__cause__) == "Mock HTTP 503"

    with MockMailjetClient(default_status=400) as mc_err:
        res_err = mc_err.contact.create(
            data=types.MappingProxyType({"Email": "x@y.com"}),
            id=11,
            action_id="manage",
            headers={"X-H": "v"},
            timeout=5,
        )
        assert res_err.status_code == 400
        assert res_err.json() == {
            "Status": "error",
            "StatusCode": 400,
            "Count": 0,
            "Total": 0,
            "Data": [],
        }
        rec = mc_err.sent_requests[-1]
        assert type(rec["data"]) is dict
        assert rec == {
            "endpoint": "contact",
            "method": "POST",
            "id": 11,
            "action_id": "manage",
            "data": {"Email": "x@y.com"},
            "filters": None,
            "headers": {"X-H": "v"},
            "kwargs": {"timeout": 5},
        }

        res_399 = MockMailjetClient(default_status=399).send.get(
            id=1, filters={"Limit": 2}, action_id="a", headers={"H": "1"}, timeout=3
        )
        assert res_399.json()["Status"] == "success"
        res_update = mc_err.contact.update(id=2, data={"k": "v"}, action_id="b", headers={"H": "2"}, timeout=4)
        assert res_update.status_code == 400
        res_patch = mc_err.contact.patch(id=3, data={"k": "p"}, action_id="c", headers={"H": "3"}, timeout=5)
        assert res_patch.status_code == 400
        res_del = mc_err.contact.delete(id=4, action_id="d", timeout=6)
        assert res_del.status_code == 400
        res_call = mc_err.contact(id=5)
        assert res_call.status_code == 400
        assert mc_err.sent_requests[-1]["method"] == "GET"

    async def _async_ctx() -> MockMailjetClient:
        async with MockMailjetClient() as amc:
            amc.contact.create(data={"Email": "async@example.com"})
            return amc

    assert len(asyncio.run(_async_ctx()).sent_requests) == 1


def test_endpoint_retry_routing_and_transport_security_mutants() -> None:
    """Kill surviving mutants across endpoint, retry, routing, and transport_security."""
    sync_client = MagicMock()
    sync_client.config.api_url = "https://api.mailjet.com/"
    sync_client.config.version = "v3"
    ep = Endpoint(sync_client, "contact")

    # Endpoint.__call__ default GET + get() method="GET"
    ep()
    assert sync_client.api_call.call_args.kwargs["method"] == "GET"
    sync_client.api_call.reset_mock()
    ep.get(id=7, filters={"Offset": 0}, action_id="sub", headers={"X-A": "1"}, timeout=4)
    assert sync_client.api_call.call_args.kwargs["method"] == "GET"
    assert sync_client.api_call.call_args.kwargs["headers"]["X-A"] == "1"

    # Endpoint.stream exact page_limit, action_id, and kwargs forwarding
    pages: list[dict[str, Any]] = [
        {"Data": [{"ID": 1}, {"ID": 2}]},
        {"Data": [{"ID": 3}, {"ID": 4}]},
    ]
    seen_get_kwargs: list[dict[str, Any]] = []

    def _fake_ep_get(**kw: Any) -> MagicMock:
        seen_get_kwargs.append(kw)
        resp = MagicMock()
        resp.status_code = 200
        resp.json.return_value = pages[len(seen_get_kwargs) - 1]
        return resp

    with patch.object(Endpoint, "get", side_effect=_fake_ep_get):
        streamed = list(ep.stream(id=10, action_id="lists", chunk_size=2, max_items=3, timeout=9))
    assert streamed == [{"ID": 1}, {"ID": 2}, {"ID": 3}]
    assert seen_get_kwargs[0]["action_id"] == "lists"
    assert seen_get_kwargs[0]["timeout"] == 9
    assert seen_get_kwargs[1]["filters"] == {"Limit": 1, "Offset": 2}

    with pytest.raises(ValueError, match="exceeds Mailjet's maximum Limit of 1000"):
        list(ep.stream(chunk_size=1001))

    # Endpoint.patch exact forwarding including ensure_ascii & data_encoding
    with patch.object(Endpoint, "__call__", return_value=MagicMock()) as mock_ep_call:
        ep.patch(
            id=3, data={"Name": "N"}, action_id="act", headers={"X-P": "1"}, ensure_ascii=True, data_encoding="latin-1"
        )
    assert mock_ep_call.call_args.kwargs == {
        "method": "PATCH",
        "id": 3,
        "data": {"Name": "N"},
        "action_id": "act",
        "headers": {"X-P": "1"},
        "ensure_ascii": True,
        "data_encoding": "latin-1",
    }

    async def _check_async_ep() -> None:
        ac = MagicMock()
        ac.config.api_url = "https://api.mailjet.com"
        ac.config.version = "v3"
        ac.api_call = AsyncMock(return_value=MagicMock())
        aep = AsyncEndpoint(ac, "contact")
        await aep()
        assert ac.api_call.call_args.kwargs["method"] == "GET"

    asyncio.run(_check_async_ep())

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
    fake_httpx2 = types.SimpleNamespace(
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

    # Routing: split_endpoint_parts, versions, trailing slash strip, stream filters Limit pop
    assert split_endpoint_parts("contact") == ("contact", "contact", ["contact"])
    assert split_endpoint_parts("tpl_UserInfo") == ("tpl_userinfo", "tpl", ["tpl", "user-info"])
    for ver in ("v1", "v3", "v3.1", "v4"):
        with patch("mailjet_rest.utils.routing.SecurityGuard.sanitize_segment", wraps=lambda s: s) as spy_seg:
            built = build_endpoint_url("contact", "contact", "contact", ["contact"], "https://api.mailjet.com/", ver)
            assert built == f"https://api.mailjet.com/{ver}/REST/contact"
            spy_seg.assert_not_called()
    assert cast_query_param("s", ["a", "b"]) == ["a", "b"]
    norm_f, norm_off = normalize_stream_filters({"Limit": "99", "Offset": "5"}, 50)
    assert norm_f == {"Limit": 50, "Offset": "5"}
    assert norm_off == 5
    assert external_stacklevel() >= 1
    with pytest.warns(DeprecationWarning):
        emit_deprecation_if_needed("newsletter", "newsletter")

    # transport_security: OP_NO_COMPRESSION preserves existing flags & coerce_httpx2_timeout tuple args
    fake_ctx = types.SimpleNamespace(minimum_version=None, check_hostname=False, verify_mode=None, options=0xFF)
    fake_ctx.load_verify_locations = MagicMock()
    with patch("mailjet_rest.utils.transport_security.ssl.create_default_context", return_value=fake_ctx):
        res_ctx = _new_secure_ssl_context(None)
    assert res_ctx.options == (0xFF | getattr(ssl, "OP_NO_COMPRESSION", 0))

    recorded_timeouts: list[tuple[tuple[Any, ...], dict[str, Any]]] = []

    class _FakeTimeout:
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            recorded_timeouts.append((args, kwargs))

    coerce_httpx2_timeout(types.SimpleNamespace(Timeout=_FakeTimeout), (2.5, 7.5))
    assert recorded_timeouts == [((7.5,), {"connect": 2.5, "read": 7.5, "write": 7.5, "pool": 2.5})]


def test_mutation_kills_testing_errors_and_retry_details(caplog: pytest.LogCaptureFixture) -> None:
    """Kill remaining non-equivalent mutants in testing.py, errors.py, and utils/retry.py."""
    # 1. MockEndpoint parameter forwarding across every HTTP helper
    mc = MockMailjetClient(default_status=201)
    mc.contact.get(id=1, filters={"Limit": 2}, action_id="a", headers={"H": "1"}, timeout=3)
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "GET",
        "id": 1,
        "action_id": "a",
        "data": None,
        "filters": {"Limit": 2},
        "headers": {"H": "1"},
        "kwargs": {"timeout": 3},
    }
    mc.contact.update(id=2, data={"k": "v"}, action_id="b", headers={"H": "2"}, timeout=4)
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "PUT",
        "id": 2,
        "action_id": "b",
        "data": {"k": "v"},
        "filters": None,
        "headers": {"H": "2"},
        "kwargs": {"timeout": 4},
    }
    mc.contact.patch(id=3, data={"k": "p"}, action_id="c", headers={"H": "3"}, timeout=5)
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "PATCH",
        "id": 3,
        "action_id": "c",
        "data": {"k": "p"},
        "filters": None,
        "headers": {"H": "3"},
        "kwargs": {"timeout": 5},
    }
    mc.contact.delete(id=4, action_id="d", timeout=6)
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "DELETE",
        "id": 4,
        "action_id": "d",
        "data": None,
        "filters": None,
        "kwargs": {"timeout": 6},
    }
    mc.contact(method="PUT", id=5, data={"x": 1}, filters={"f": 2}, action_id="e", headers={"H": "9"}, timeout=7)
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "PUT",
        "id": 5,
        "action_id": "e",
        "data": {"x": 1},
        "filters": {"f": 2},
        "headers": {"H": "9"},
        "kwargs": {"timeout": 7},
    }

    # 2. errors.py exact max_chars forwarding and timeout logger formatting
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

    # 3. utils/retry.py JitterRetry (0 < backoff <= 1), bounded_exponent 20 vs 21, and run_async_with_retries logging/rewind
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

    fake_httpx2 = types.SimpleNamespace(
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
        return types.SimpleNamespace(status_code=200, headers={})

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
    no_closed_attr_resp = types.SimpleNamespace(status_code=429, headers={}, aclose=AsyncMock())
    seq2 = iter([no_closed_attr_resp, types.SimpleNamespace(status_code=200)])

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
