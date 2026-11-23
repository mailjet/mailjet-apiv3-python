"""Unit tests for asynchronous endpoint execution, routing, ID validation, and stream pagination (AsyncEndpoint)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock, MagicMock
from urllib.parse import parse_qs

import pytest

from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import MailjetApiError


# ==========================================
# 1. Asynchronous CRUD & Header Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_crud_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncEndpoint get, create, update, delete, legacy args, and custom header merging."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        async with AsyncClient(auth=("key", "secret"), version="v3") as aclient:
            ep: AsyncEndpoint = aclient.contact
            req = httpx2_mod.Request("GET", "https://api.mailjet.com/v3/REST/contact")

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=httpx2_mod.Response(200, json={"Data": []}, request=req)),
            )
            r_get = await ep.get(headers={"X-Trace": "123"})
            assert r_get.status_code == 200

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=httpx2_mod.Response(201, json={"Data": [{"ID": 1}]}, request=req)),
            )
            r_create = await ep.create(data={"Email": "async@example.com"})
            assert r_create.status_code == 201

            with pytest.warns(DeprecationWarning, match="ensure_ascii"):
                r_legacy = await ep.create(
                    data={"Email": "async@example.com"}, ensure_ascii=True, data_encoding="utf-8"
                )
            assert r_legacy.status_code == 201

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=httpx2_mod.Response(200, json={"Data": [{"ID": 1}]}, request=req)),
            )
            r_update = await ep.update(id=1, data={"Name": "Updated"})
            assert r_update.status_code == 200

            assert repr(ep) == "<AsyncEndpoint name='contact'>"

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=httpx2_mod.Response(204, request=req)),
            )
            r_delete = await ep.delete(id=1)
            assert r_delete.status_code == 204

            for bad_id in ("", "   ", True):
                with pytest.raises(ValueError, match="non-empty, non-boolean"):
                    await ep.delete(id=bad_id)

    asyncio.run(_run())


# ==========================================
# 2. Asynchronous Stream & Validation Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_stream_pagination_and_edge_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncEndpoint multi-page streaming, max_items, fail-loud errors, and input validation."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        async with AsyncClient(auth=("key", "secret"), version="v3") as aclient:
            ep: AsyncEndpoint = aclient.contact
            req = httpx2_mod.Request("GET", "https://api.mailjet.com/v3/REST/contact")

            # 1. Multi-page async stream pagination
            pages = [
                httpx2_mod.Response(200, json={"Data": [{"ID": 1}, {"ID": 2}]}, request=req),
                httpx2_mod.Response(200, json={"Data": [{"ID": 3}]}, request=req),
            ]
            monkeypatch.setattr(aclient.session, "request", AsyncMock(side_effect=pages))
            items = [item async for item in ep.stream(chunk_size=2)]
            assert items == [{"ID": 1}, {"ID": 2}, {"ID": 3}]

            # 2. max_items=0 returns immediately without network calls; max_items=N caps output
            spy = AsyncMock()
            monkeypatch.setattr(aclient.session, "request", spy)
            assert [item async for item in ep.stream(chunk_size=10, max_items=0)] == []
            assert spy.call_count == 0

            cap_page = httpx2_mod.Response(200, json={"Data": [{"ID": 10}, {"ID": 11}]}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=cap_page))
            assert [item async for item in ep.stream(chunk_size=10, max_items=2)] == [{"ID": 10}, {"ID": 11}]

            # 3. Empty collection exits after a single page
            empty_page = httpx2_mod.Response(200, json={"Data": []}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=empty_page))
            assert [item async for item in ep.stream(chunk_size=10)] == []

            # 4. Fail-loud MailjetApiError on malformed stream responses (Wave 4 parity)
            bad_json = httpx2_mod.Response(200, text="not-json", request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=bad_json))
            with pytest.raises(MailjetApiError, match="Malformed JSON body"):
                _ = [item async for item in ep.stream(chunk_size=2)]

            list_json = httpx2_mod.Response(200, json=[1, 2], request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=list_json))
            with pytest.raises(MailjetApiError, match="Expected JSON object"):
                _ = [item async for item in ep.stream(chunk_size=2)]

            bad_data = httpx2_mod.Response(200, json={"Data": "not-a-list"}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=bad_data))
            with pytest.raises(MailjetApiError, match="Expected 'Data' list"):
                _ = [item async for item in ep.stream(chunk_size=2)]

            # 5. Input validation errors
            with pytest.raises(ValueError, match=r"stream\(\) is designed for GET requests only"):
                _ = [item async for item in ep.stream(method="POST")]

            with pytest.raises(ValueError, match=r"chunk_size must be a strictly positive integer"):
                _ = [item async for item in ep.stream(chunk_size=0)]

            with pytest.raises(ValueError, match=r"exceeds Mailjet's maximum Limit of 1000"):
                _ = [item async for item in ep.stream(chunk_size=1001)]

            with pytest.raises(ValueError, match=r"max_items must be a non-negative integer"):
                _ = [item async for item in ep.stream(max_items=-1)]

            with pytest.raises(ValueError, match=r"stream\(\) Offset filter must be an integer"):
                _ = [item async for item in ep.stream(filters={"offset": "bad"})]

    asyncio.run(_run())


# ==========================================
# 3. Argument Forwarding & Mutant Kills
# ==========================================


def test_async_endpoint_update_forward_all_args() -> None:
    """Kill survived argument-forwarding mutants in AsyncEndpoint.update."""

    async def _run_async() -> None:
        async_client = MagicMock()
        async_client.config.api_url = "https://api.mailjet.com"
        async_client.config.version = "v3"
        sentinel = MagicMock()
        async_client.api_call = AsyncMock(return_value=sentinel)
        aep = AsyncEndpoint(async_client, "contact")

        with pytest.warns(DeprecationWarning, match="deprecated"):
            res = await aep.update(
                id=9,
                data={"Name": "AsyncUpdated"},
                action_id="act",
                headers={"X-Async": "2"},
                ensure_ascii=False,
                data_encoding="utf-8",
                timeout=9,
            )
        assert res is sentinel
        async_client.api_call.assert_awaited_once()
        a_kw = async_client.api_call.call_args.kwargs
        assert a_kw["method"] == "PUT"
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


def test_async_endpoint_default_get_call() -> None:
    """Kill survived default method mutant in AsyncEndpoint.__call__."""

    async def _check_async_ep() -> None:
        ac = MagicMock()
        ac.config.api_url = "https://api.mailjet.com"
        ac.config.version = "v3"
        ac.api_call = AsyncMock(return_value=MagicMock())
        aep = AsyncEndpoint(ac, "contact")
        await aep()
        assert ac.api_call.call_args.kwargs["method"] == "GET"

    asyncio.run(_check_async_ep())


# ==========================================
# 4. Sync-to-Async Endpoint Parity Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_dynamic_action_id_and_data_routing() -> None:
    """Verify AsyncEndpoint parity for camelCase hyphenation, dynamic action_id shifts, and DATA routing."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        seen_requests: list[tuple[str, str]] = []

        def handler(request: Any) -> Any:
            seen_requests.append((request.method, str(request.url)))
            return httpx2_mod.Response(200, json={})

        async with AsyncClient(
            auth=("key", "secret"),
            version="v3",
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            # CamelCase-to-kebab conversion & action parts
            ep1 = AsyncEndpoint(aclient, "customResource_linkClick")
            assert ep1._resource_lower == "customresource"
            assert ep1._action_parts == ["customresource", "link-click"]
            ep2 = AsyncEndpoint(aclient, "customResource_LinkClick")
            assert ep2._action_parts == ["customresource", "link-click"]
            ep3 = AsyncEndpoint(aclient, "myResource_firstAction_secondActionName")
            assert ep3._resource_lower == "myresource"
            assert ep3._action_parts == ["myresource", "first-action", "second-action-name"]
            ep4 = AsyncEndpoint(aclient, "simpleresource")
            assert ep4._action_parts == ["simpleresource"]

            # Dynamic action_id & DATA route construction
            assert (
                aclient.contact_custom._build_url(id_val=123, action_id=456)
                == "https://api.mailjet.com/v3/REST/contact/123/custom/456"
            )
            assert (
                aclient.customResource_someAction._build_url(action_id=456)
                == "https://api.mailjet.com/v3/REST/customresource/456/some-action"
            )
            assert (
                aclient.customResource_someAction._build_url(id_val=123)
                == "https://api.mailjet.com/v3/REST/customresource/123/some-action"
            )
            assert (
                aclient.customResource_someAction._build_url(id_val=123, action_id=456)
                == "https://api.mailjet.com/v3/REST/customresource/123/some-action/456"
            )
            assert (
                aclient.customResource_someAction._build_url()
                == "https://api.mailjet.com/v3/REST/customresource/some-action"
            )
            assert aclient.data_testroute._build_url() == "https://api.mailjet.com/v3/data/testroute"
            assert (
                aclient.data_custom_path._build_url(action_id="sub_token")
                == "https://api.mailjet.com/v3/data/custom/path/sub_token"
            )

            # Live async execution over MockTransport for CSVData & data_* dynamic routes
            res_csv = await aclient.contactslist_csvdata.get(id="123")
            assert res_csv.status_code == 200
            res_data = await aclient.data_custom_path.get(action_id="sub_token")
            assert res_data.status_code == 200

        assert seen_requests == [
            ("GET", "https://api.mailjet.com/v3/DATA/contactslist/123/CSVData/text:plain"),
            ("GET", "https://api.mailjet.com/v3/data/custom/path/sub_token"),
        ]

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_update_and_delete_id_validation() -> None:
    """Verify AsyncEndpoint update/delete reject missing, blank, or boolean IDs while preserving empty update."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        seen_puts: list[str] = []

        def handler(request: Any) -> Any:
            seen_puts.append(f"{request.method} {request.url}")
            return httpx2_mod.Response(200, json={"success": True})

        async with AsyncClient(
            auth=("key", "secret"),
            version="v3",
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            for bad_id in (None, "", "   ", True, False):
                with pytest.raises(
                    ValueError,
                    match=r"AsyncEndpoint\.delete\(\) requires a non-empty, non-boolean resource 'id'\.",
                ):
                    await aclient.contact.delete(id=bad_id)  # type: ignore[arg-type]

            # Missing required {id} on parameterized registry route raises ValueError on update()
            with pytest.raises(ValueError, match="requires an 'id' parameter"):
                await aclient.contact_getcontactslists.update(data={"Name": "MissingID"})

            # Boolean IDs are rejected by segment sanitization on update()
            for bad_bool in (True, False):
                with pytest.raises(TypeError, match="Invalid segment type bool"):
                    await aclient.contact.update(id=bad_bool, data={"Name": "BoolID"})

            # Empty string ID on unparameterized route still resolves trailing slash PUT for legacy parity
            res_empty = await aclient.contact.update(id="", data={"Name": "New"})
            assert res_empty.status_code == 200

        assert seen_puts == ["PUT https://api.mailjet.com/v3/REST/contact/"]

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_stream_filter_normalization_and_snapshot_isolation() -> None:
    """Verify AsyncEndpoint.stream strips Limit/limit casings and isolates caller filter dicts."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    filters = {"limit": 50, "Limit": 100, "Offset": 0}
    clean_filters, offset = AsyncEndpoint._normalize_stream_filters(filters, chunk_size=500)
    assert offset == 0
    assert clean_filters["Limit"] == 500
    assert "limit" not in clean_filters

    async def _run() -> None:
        observed_params: list[dict[str, str]] = []

        def handler(request: Any) -> Any:
            observed_params.append(dict(request.url.params))
            return httpx2_mod.Response(200, json={"Total": 1, "Data": [{"id": 100}]})

        async with AsyncClient(
            auth=("key", "secret"),
            version="v3",
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            initial_filters = {"offset": "20", "limit": "5", "Custom": "KeepMe"}
            items = [item async for item in aclient.contact.stream(filters=initial_filters, chunk_size=50)]

        assert items == [{"id": 100}]
        assert initial_filters == {"offset": "20", "limit": "5", "Custom": "KeepMe"}
        assert len(observed_params) == 1
        assert observed_params[0]["Offset"] == "20"
        assert observed_params[0]["Limit"] == "50"
        assert observed_params[0]["Custom"] == "KeepMe"
        assert "offset" not in observed_params[0]
        assert "limit" not in observed_params[0]

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_stream_with_parse_qs_multidict() -> None:
    """Ensure AsyncEndpoint.stream() seamlessly consumes parse_qs output without TypeError."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        captured_offsets: list[int] = []

        def handler(request: Any) -> Any:
            req_offset = int(request.url.params["Offset"])
            captured_offsets.append(req_offset)
            if req_offset == 10:
                return httpx2_mod.Response(200, json={"Total": 13, "Data": [{"id": 1}, {"id": 2}]})
            return httpx2_mod.Response(200, json={"Total": 13, "Data": [{"id": 3}]})

        async with AsyncClient(
            auth=("key", "secret"),
            version="v3",
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            raw_query = parse_qs("offset=10&limit=2")
            items = [item async for item in aclient.contact.stream(filters=raw_query, chunk_size=2)]

        assert len(items) == 3
        assert items == [{"id": 1}, {"id": 2}, {"id": 3}]
        assert captured_offsets == [10, 12]

    asyncio.run(_run())
