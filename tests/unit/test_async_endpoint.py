"""Unit tests for asynchronous endpoint execution and pagination (AsyncEndpoint)."""

from __future__ import annotations

import asyncio
from typing import Any
from unittest.mock import AsyncMock

import pytest

from mailjet_rest.client import AsyncClient, Client, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
from mailjet_rest.errors import MailjetApiError


# ==========================================
# 1. Asynchronous CRUD & Header Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_crud_operations(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncEndpoint get, create, update, delete, legacy args, and custom header merging."""

    async def _run() -> None:
        async with AsyncClient(auth=("key", "secret"), version="v3") as aclient:
            ep: AsyncEndpoint = aclient.contact
            req = _httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=_httpx2.Response(200, json={"Data": []}, request=req)),
            )
            r_get = await ep.get(headers={"X-Trace": "123"})
            assert r_get.status_code == 200

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=_httpx2.Response(201, json={"Data": [{"ID": 1}]}, request=req)),
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
                AsyncMock(return_value=_httpx2.Response(200, json={"Data": [{"ID": 1}]}, request=req)),
            )
            r_update = await ep.update(id=1, data={"Name": "Updated"})
            assert r_update.status_code == 200

            assert repr(ep) == "<AsyncEndpoint name='contact'>"
            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(
                    return_value=_httpx2.Response(200, json={"Data": [{"ID": 1, "Name": "Patched"}]}, request=req)
                ),
            )
            r_patch = await ep.patch(id=1, data={"Name": "Patched"})
            assert r_patch.status_code == 200

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(return_value=_httpx2.Response(204, request=req)),
            )
            r_delete = await ep.delete(id=1)
            assert r_delete.status_code == 204

            for bad_id in ("", "   ", True):
                with pytest.raises(ValueError, match="non-empty, non-boolean"):
                    await ep.delete(id=bad_id)

    asyncio.run(_run())

    # Sync Endpoint repr and patch parity
    with Client(auth=("key", "secret"), version="v3") as sync_client:
        sync_ep: Endpoint = sync_client.contact
        assert repr(sync_ep) == "<Endpoint name='contact'>"
        captured: dict[str, Any] = {}

        def fake_sync_request(**kwargs: Any) -> Any:
            captured.update(kwargs)
            return type("Resp", (), {"status_code": 200, "raise_for_status": lambda _s=None: None})()

        monkeypatch.setattr(sync_client.session, "request", fake_sync_request)
        sync_resp = sync_ep.patch(id=42, data={"Name": "SyncPatched"})
        assert sync_resp.status_code == 200
        assert captured["method"] == "PATCH"
        assert captured["url"].endswith("/v3/REST/contact/42")


# ==========================================
# 2. Asynchronous Stream & Validation Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_endpoint_stream_pagination_and_edge_cases(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncEndpoint multi-page streaming, max_items, fail-loud errors, and input validation."""

    async def _run() -> None:
        async with AsyncClient(auth=("key", "secret"), version="v3") as aclient:
            ep: AsyncEndpoint = aclient.contact
            req = _httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")

            # 1. Multi-page async stream pagination
            pages = [
                _httpx2.Response(200, json={"Data": [{"ID": 1}, {"ID": 2}]}, request=req),
                _httpx2.Response(200, json={"Data": [{"ID": 3}]}, request=req),
            ]
            monkeypatch.setattr(aclient.session, "request", AsyncMock(side_effect=pages))
            items = [item async for item in ep.stream(chunk_size=2)]
            assert items == [{"ID": 1}, {"ID": 2}, {"ID": 3}]

            # 2. max_items=0 returns immediately without network calls; max_items=N caps output
            spy = AsyncMock()
            monkeypatch.setattr(aclient.session, "request", spy)
            assert [item async for item in ep.stream(chunk_size=10, max_items=0)] == []
            assert spy.call_count == 0

            cap_page = _httpx2.Response(200, json={"Data": [{"ID": 10}, {"ID": 11}]}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=cap_page))
            assert [item async for item in ep.stream(chunk_size=10, max_items=2)] == [{"ID": 10}, {"ID": 11}]

            # 3. Empty collection exits after a single page
            empty_page = _httpx2.Response(200, json={"Data": []}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=empty_page))
            assert [item async for item in ep.stream(chunk_size=10)] == []

            # 4. Fail-loud MailjetApiError on malformed stream responses (Wave 4 parity)
            bad_json = _httpx2.Response(200, text="not-json", request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=bad_json))
            with pytest.raises(MailjetApiError, match="Malformed JSON body"):
                _ = [item async for item in ep.stream(chunk_size=2)]

            list_json = _httpx2.Response(200, json=[1, 2], request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=list_json))
            with pytest.raises(MailjetApiError, match="Expected JSON object"):
                _ = [item async for item in ep.stream(chunk_size=2)]

            bad_data = _httpx2.Response(200, json={"Data": "not-a-list"}, request=req)
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
