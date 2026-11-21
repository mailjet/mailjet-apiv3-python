"""Mutation-killing contract tests for Endpoint, AsyncEndpoint, and utils/routing.py."""

from __future__ import annotations

import asyncio
import warnings
from types import MappingProxyType, SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest

from mailjet_rest.client import _httpx2
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.utils.routing import (
    build_endpoint_url,
    emit_deprecation_if_needed,
    external_stacklevel,
    normalize_stream_filters,
    parse_stream_page,
    prepare_call_payload_and_headers,
    split_endpoint_parts,
)


def test_sync_endpoint_stream_multi_page_limit_and_patch_id_guard() -> None:
    """Verify multi-page Endpoint.stream yielded accounting, Limit override, and patch(id=...) action name."""
    recorded_calls: list[dict[str, Any]] = []
    pages = [
        {"Data": [{"ID": 1}, {"ID": 2}]},
        {"Data": [{"ID": 3}, {"ID": 4}]},
        {"Data": [{"ID": 5}, {"ID": 6}]},
    ]

    class _SyncStubClient:
        config = SimpleNamespace(version="v3", api_url="https://api.mailjet.com/")

        def api_call(self, **kwargs: Any) -> Any:
            recorded_calls.append(kwargs)
            page = pages[len(recorded_calls) - 1]
            return SimpleNamespace(status_code=200, text="ok", json=lambda p=page: p)

    ep = Endpoint(_SyncStubClient(), "contact")
    with pytest.raises(ValueError, match=r"Endpoint\.patch\(\) requires a non-empty"):
        ep.patch(id="", data={"Name": "bad"})

    collected = list(ep.stream(chunk_size=2, max_items=5, filters={"Limit": 99, "Offset": "4"}))
    assert [row["ID"] for row in collected] == [1, 2, 3, 4, 5]
    # Second request uses chunk_size=2 at offset=6; third request caps Limit to remaining 1 item
    assert recorded_calls[0]["filters"] == {"Offset": 4, "Limit": 2}
    assert recorded_calls[1]["filters"] == {"Offset": 6, "Limit": 2}
    assert recorded_calls[2]["filters"] == {"Offset": 8, "Limit": 1}


def test_async_endpoint_verbs_kwargs_and_multi_page_stream_contracts() -> None:
    """Verify AsyncEndpoint get/create/update/patch/delete forwarding and multi-page streaming."""
    if _httpx2 is None:
        pytest.skip("httpx2 optional extra not installed")

    recorded: list[dict[str, Any]] = []
    pages = [
        {"Data": [{"ID": 10}, {"ID": 11}]},
        {"Data": [{"ID": 12}, {"ID": 13}]},
        {"Data": [{"ID": 14}]},
    ]

    class _AsyncStubClient:
        config = SimpleNamespace(version="v3", api_url="https://api.mailjet.com/")

        async def api_call(self, **kwargs: Any) -> Any:
            recorded.append(kwargs)
            filters = kwargs.get("filters") or {}
            if kwargs["method"] == "GET" and "Limit" in filters:
                stream_idx = (
                    sum(1 for r in recorded if r["method"] == "GET" and "Limit" in (r.get("filters") or {})) - 1
                )
                page = pages[stream_idx]
                return SimpleNamespace(status_code=200, text="ok", json=lambda p=page: p)
            return SimpleNamespace(status_code=200, text="ok", json=dict)

    ep = AsyncEndpoint(_AsyncStubClient(), "contactslist")

    async def _exercise() -> None:
        await ep.get(id=1, action_id="recipients", filters={"IsActive": True}, headers={"X-Test": "1"}, timeout=9.0)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            await ep.create(
                data={"Name": "café"},
                id=2,
                action_id="managecontact",
                headers={"X-C": "2"},
                ensure_ascii=False,
                data_encoding="utf-8",
            )
            await ep.update(
                id=3,
                data={"Name": "café"},
                action_id="meta",
                headers={"X-U": "3"},
                ensure_ascii=False,
                data_encoding="utf-8",
            )
            await ep.patch(
                id=4,
                data={"Name": "café"},
                action_id="partial",
                headers={"X-P": "4"},
                ensure_ascii=False,
                data_encoding="utf-8",
            )
        await ep.delete(id=5, action_id="sub", timeout=7.0)

        streamed = [item async for item in ep.stream(id=9, action_id="contacts", chunk_size=2, max_items=5)]
        assert [row["ID"] for row in streamed] == [10, 11, 12, 13, 14]

    asyncio.run(_exercise())

    assert [(r["method"], r["url"]) for r in recorded[:5]] == [
        ("GET", "https://api.mailjet.com/v3/REST/contactslist/1/recipients"),
        ("POST", "https://api.mailjet.com/v3/REST/contactslist/2/managecontact"),
        ("PUT", "https://api.mailjet.com/v3/REST/contactslist/3/meta"),
        ("PATCH", "https://api.mailjet.com/v3/REST/contactslist/4/partial"),
        ("DELETE", "https://api.mailjet.com/v3/REST/contactslist/5/sub"),
    ]
    assert recorded[0]["headers"]["X-Test"] == "1"
    assert recorded[0]["timeout"] == 9.0
    assert recorded[1]["data"] == '{"Name": "café"}'.encode()
    assert recorded[2]["data"] == '{"Name": "café"}'.encode()
    assert recorded[3]["data"] == '{"Name": "café"}'.encode()
    assert recorded[4]["timeout"] == 7.0
    # Stream requests forward id, action_id, and Limit=2 -> remaining 1
    assert recorded[5]["url"] == "https://api.mailjet.com/v3/REST/contactslist/9/contacts"
    assert recorded[7]["filters"] == {"Offset": 4, "Limit": 1}


def test_routing_url_stacklevel_filters_parse_error_and_mappingproxy_contracts() -> None:
    """Verify exact routing normalization, deprecation stacklevel, MappingProxyType JSON, and parse_stream_page errors."""
    assert split_endpoint_parts("contact") == ("contact", "contact", ["contact"])
    assert external_stacklevel() >= 1

    with pytest.warns(DeprecationWarning, match="Migrate to 'campaigndraft'"):
        emit_deprecation_if_needed("custom_sub", "newsletter")

    assert (
        build_endpoint_url(
            "contact",
            "contact",
            "contact",
            ["contact"],
            "https://api.mailjet.com///",
            "v3",
            action_id="detail",
        )
        == "https://api.mailjet.com/v3/REST/contact/detail"
    )

    clean_filters, offset = normalize_stream_filters({"Limit": 500, "Offset": "0"}, chunk_size=100)
    assert clean_filters == {"Offset": "0", "Limit": 100}
    assert offset == 0

    for bad_resp, msg_pat in (
        (
            SimpleNamespace(status_code=502, text="not-json", json=MagicMock(side_effect=ValueError("bad"))),
            "Malformed JSON",
        ),
        (SimpleNamespace(status_code=200, text="[]", json=list), "Expected JSON object"),
        (SimpleNamespace(status_code=200, text='{"Data": 1}', json=lambda: {"Data": "bad"}), "Expected 'Data' list"),
    ):
        with pytest.raises(MailjetApiError, match=msg_pat) as err:
            parse_stream_page(bad_resp)
        assert err.value.status_code == bad_resp.status_code
        assert err.value.response_body == bad_resp.text

    with pytest.warns(DeprecationWarning, match="deprecated"):
        hdrs, payload = prepare_call_payload_and_headers(
            "contact",
            MappingProxyType({"Name": "€"}),
            None,
            {"headers": {"X-H": "v"}, "ensure_ascii": None, "data_encoding": "utf-8"},
        )
    assert hdrs["X-H"] == "v"
    assert payload == b'{"Name": "\\u20ac"}'
