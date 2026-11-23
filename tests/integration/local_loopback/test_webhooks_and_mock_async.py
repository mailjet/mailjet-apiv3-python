"""Offline loopback HTTP webhook verification and MockMailjetClient parity tests (async)."""

from __future__ import annotations

import asyncio
import json
import time
import types
from typing import Any

import pytest

from mailjet_rest import ApiRateLimitError, MailjetApiError, MockMailjetClient, ValidationError
from mailjet_rest.client import _httpx2
from mailjet_rest.testing import MockEndpoint, MockResponse, _MockStreamIterator
from tests.integration.local_loopback._servers import (
    _WEBHOOK_SECRET,
    _WebhookHTTPServer,
    _sign_webhook_payload,
)


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed.")


def test_webhook_loopback_http_async_httpx2_verification(webhook_server: tuple[str, _WebhookHTTPServer]) -> None:
    """Verify loopback webhook HTTP POST behavior using async httpx2 client across valid and invalid cases."""
    url, server = webhook_server
    server.verified_requests.clear()
    server.rejected_requests.clear()

    now = int(time.time())
    payload = json.dumps({"event": "open", "time": now, "MessageID": 123456789}).encode("utf-8")
    raw_sig = _sign_webhook_payload(payload, _WEBHOOK_SECRET)
    sig_ts = _sign_webhook_payload(payload, _WEBHOOK_SECRET, timestamp_unix=now, signed_timestamp=True)

    async def _run() -> None:
        assert _httpx2 is not None
        async with _httpx2.AsyncClient(trust_env=False, timeout=5.0) as client:
            # 1. Valid raw-payload HMAC
            ok_raw = await client.post(url, content=payload, headers={"X-Mailjet-Signature": raw_sig})
            assert ok_raw.status_code == 200
            assert ok_raw.json() == {"verified": True}

            # 2. Valid "SHA256=<UPPERCASE_HEX>" prefix normalization with signed_timestamp=True
            ok_resp = await client.post(
                url,
                content=payload,
                headers={
                    "X-Mailjet-Signature": f"SHA256={sig_ts.upper()}",
                    "X-Mailjet-Timestamp": str(now),
                    "X-Verify-Mode": "signed-ts",
                },
            )
            assert ok_resp.status_code == 200
            assert ok_resp.json() == {"verified": True}

            # 3. Valid timestamp window under raw mode
            ok_window = await client.post(
                url,
                content=payload,
                headers={
                    "X-Mailjet-Signature": raw_sig,
                    "X-Mailjet-Timestamp": str(now - 30),
                    "X-Max-Age": "300",
                },
            )
            assert ok_window.status_code == 200

            # 4. Stale/expired and far-future timestamps outside max_age_seconds -> 401
            bad_expired = await client.post(
                url,
                content=payload,
                headers={
                    "X-Mailjet-Signature": raw_sig,
                    "X-Mailjet-Timestamp": str(now - 600),
                    "X-Max-Age": "300",
                },
            )
            assert bad_expired.status_code == 401
            assert bad_expired.json() == {"verified": False}

            bad_future = await client.post(
                url,
                content=payload,
                headers={
                    "X-Mailjet-Signature": raw_sig,
                    "X-Mailjet-Timestamp": str(now + 600),
                    "X-Max-Age": "300",
                },
            )
            assert bad_future.status_code == 401

            # 5. Tampered timestamp under signed_timestamp=True -> 401
            bad_tampered_ts = await client.post(
                url,
                content=payload,
                headers={
                    "X-Mailjet-Signature": sig_ts,
                    "X-Mailjet-Timestamp": str(now - 1),
                    "X-Verify-Mode": "signed-ts",
                },
            )
            assert bad_tampered_ts.status_code == 401

            # 6. Missing timestamp_unix when signed_timestamp=True -> 400
            bad_missing_ts = await client.post(
                url,
                content=payload,
                headers={"X-Mailjet-Signature": sig_ts, "X-Verify-Mode": "signed-ts"},
            )
            assert bad_missing_ts.status_code == 400
            assert "timestamp_unix is required" in bad_missing_ts.json()["error"]

            # 7. Tampered payload bytes -> 401
            bad_resp = await client.post(
                url,
                content=payload + b" ",
                headers={
                    "X-Mailjet-Signature": sig_ts,
                    "X-Mailjet-Timestamp": str(now),
                    "X-Verify-Mode": "signed-ts",
                },
            )
            assert bad_resp.status_code == 401
            assert bad_resp.json() == {"verified": False}

    asyncio.run(_run())
    assert len(server.verified_requests) == 3
    assert server.verified_requests[0]["payload"] == payload
    assert len(server.rejected_requests) == 5


def test_mock_mailjet_client_async_workflow() -> None:
    """Exercise async parity workflows on MockMailjetClient, MockEndpoint, and MockResponse."""

    async def _run_async() -> None:
        async with MockMailjetClient() as amock:
            contact_ep = amock.contact
            assert isinstance(contact_ep, MockEndpoint)

            get_res = await contact_ep.get(
                id=42, filters={"Limit": 5}, action_id="manage", headers={"X-Trace": "async"}, timeout=2.0
            )
            assert isinstance(get_res, MockResponse)
            assert get_res.status_code == 200
            get_res.raise_for_status()

            json_copy = get_res.json()
            assert json_copy == {"Status": "success", "StatusCode": 200, "Count": 0, "Total": 0, "Data": []}
            json_copy["Status"] = "mutated"
            assert get_res.json()["Status"] == "success"

            aresp = await amock.send_v31.create(data={"Messages": [{"Subject": "Async Test"}]})
            assert isinstance(aresp, MockResponse)
            assert aresp.status_code == 200
            assert aresp.json()["Status"] == "success"
            awaitable_iter = iter(aresp.__await__())
            with pytest.raises(StopIteration) as stop_exc:
                next(awaitable_iter)
            assert stop_exc.value.value is aresp

            update_res = await amock.contact.update(id=42, data={"Name": "Updated Async"})
            assert update_res.status_code == 200

            proxy_payload = types.MappingProxyType({"IsExcludedFromCampaigns": True})
            patch_res = await amock.contact.patch(id=42, data=proxy_payload, headers={"X-Patch": "1"}, extra_flag="yes")
            assert patch_res.status_code == 200

            delete_res = await amock.contact.delete(id=42, action_id="purge")
            assert delete_res.status_code == 200

            call_res = await amock.contact("GET", filters={"Limit": 5})
            assert call_res.status_code == 200

            assert await amock.ping() is True
            streamed = [
                item async for item in amock.contact.stream(filters={"IsExcludedFromCampaigns": False}, chunk_size=25)
            ]
            assert streamed == []

            with pytest.raises(AttributeError, match="_hidden"):
                _ = amock._hidden

        assert len(amock.sent_requests) == 7
        assert amock.sent_requests[0]["method"] == "GET"
        assert amock.sent_requests[0]["headers"] == {"X-Trace": "async"}
        assert amock.sent_requests[0]["kwargs"] == {"timeout": 2.0}
        patch_record = amock.sent_requests[3]
        assert patch_record["method"] == "PATCH"
        assert type(patch_record["data"]) is dict
        assert patch_record["data"] == {"IsExcludedFromCampaigns": True}
        assert patch_record["headers"] == {"X-Patch": "1"}
        assert patch_record["kwargs"] == {"extra_flag": "yes"}
        assert amock.sent_requests[6]["method"] == "GET"
        assert amock.sent_requests[6]["filters"] == {"IsExcludedFromCampaigns": False}

        # Manual aclose lifecycle
        manual_mock = MockMailjetClient()
        assert await manual_mock.ping() is True
        await manual_mock.aclose()

    asyncio.run(_run_async())


def test_mock_mailjet_client_async_errors_streaming_ping_and_validation() -> None:
    """Exercise async MockMailjetClient error status mapping, async stream iterators, async ping, and ID guards."""

    async def _run_async() -> None:
        async with MockMailjetClient(default_status=400) as bad_req:
            resp_400 = await bad_req.contact.create(data={"Email": "bad"})
            assert resp_400.json()["Status"] == "error"
            with pytest.raises(ValidationError):
                resp_400.raise_for_status()

        async with MockMailjetClient(default_status=429) as rate_limited:
            resp_429 = await rate_limited.contact.get()
            with pytest.raises(ApiRateLimitError):
                resp_429.raise_for_status()

        async with MockMailjetClient(default_status=500) as server_err:
            resp_500 = await server_err.contact.get()
            with pytest.raises(MailjetApiError):
                resp_500.raise_for_status()

        async with MockMailjetClient() as mock:
            for invalid_id in ("", "   ", None, True, False):
                with pytest.raises(ValueError, match="non-empty, non-boolean resource 'id'"):
                    await mock.contact.patch(id=invalid_id, data={})  # type: ignore[arg-type]
                with pytest.raises(ValueError, match="non-empty, non-boolean resource 'id'"):
                    await mock.contact.delete(id=invalid_id)  # type: ignore[arg-type]

            with pytest.raises(ValueError, match="chunk_size"):
                _ = [item async for item in mock.contact.stream(chunk_size=0)]
            with pytest.raises(ValueError, match="chunk_size"):
                _ = [item async for item in mock.contact.stream(chunk_size=1001)]
            with pytest.raises(ValueError, match="GET requests only"):
                _ = [item async for item in mock.contact.stream(method="POST")]

        async_iter = _MockStreamIterator(({"ID": 10}, {"ID": 20}))
        items: list[dict[str, Any]] = [item async for item in async_iter]
        assert items == [{"ID": 10}, {"ID": 20}]

        async with (
            MockMailjetClient(default_status=200) as ok_client,
            MockMailjetClient(default_status=503) as fail_client,
        ):
            assert await ok_client.ping(timeout=1.5) is True
            assert await fail_client.ping() is False

    asyncio.run(_run_async())
