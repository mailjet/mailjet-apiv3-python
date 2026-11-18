"""Targeted unit tests killing survived and untested mutants across core modules."""

from __future__ import annotations

import asyncio
import email.utils
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from mailjet_rest.builders import MessageBuilder
from mailjet_rest.endpoint import AsyncEndpoint, BaseEndpoint, Endpoint
from mailjet_rest.utils.retry import JitterRetry, compute_retry_delay
from mailjet_rest.utils.version import get_version, parse_semver_triplet


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
