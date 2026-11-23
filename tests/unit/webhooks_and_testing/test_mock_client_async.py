"""Asynchronous unit tests for mailjet_rest.testing in-memory test doubles."""

from __future__ import annotations

import asyncio
import types
from typing import Any

import pytest

from mailjet_rest.errors import (
    ApiRateLimitError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    ValidationError,
)
from mailjet_rest.testing import (
    MockEndpoint,
    MockMailjetClient,
    MockResponse,
    _MockStreamIterator,
)


def test_mock_mailjet_client_async_context_manager_and_error_status() -> None:
    """Migrated async context manager checks with awaitable MockResponse and DoesNotExistError."""

    async def _async_ctx() -> MockMailjetClient:
        async with MockMailjetClient(default_status=404) as aclient:
            resp = await aclient.contact.get(id=999)
            assert resp.status_code == 404
            with pytest.raises(DoesNotExistError):
                resp.raise_for_status()

        async with MockMailjetClient() as amc:
            create_resp = await amc.contact.create(data={"Email": "async@example.com"})
            assert create_resp.status_code == 200
            return amc

    recorded_client = asyncio.run(_async_ctx())
    assert len(recorded_client.sent_requests) == 1
    assert recorded_client.sent_requests[0]["data"] == {"Email": "async@example.com"}


def test_mock_mailjet_client_async_endpoints_crud_and_parameter_forwarding() -> None:
    """Async 1:1 parity for MockEndpoint CRUD, __call__, MappingProxyType, headers, kwargs, and slots."""

    async def _run() -> None:
        async with MockMailjetClient() as aclient:
            assert not hasattr(aclient, "__dict__")
            endpoint = aclient.send_v31
            assert isinstance(endpoint, MockEndpoint)
            assert not hasattr(endpoint, "__dict__")

            create_resp = await endpoint.create(data={"Messages": [{"Subject": "Hi"}]}, headers={"X-Test": "1"})
            assert isinstance(create_resp, MockResponse)
            assert not hasattr(create_resp, "__dict__")
            assert create_resp.status_code == 200
            assert create_resp.json()["Status"] == "success"
            create_resp.raise_for_status()

            await aclient.contact.get(id=42, filters={"Limit": 5})
            await aclient.contact.update(id=42, data={"Name": "Updated"})
            await aclient.contact.patch(id=42, data={"Name": "Patched"})
            await aclient.contact.delete(id=42)
            await aclient.contact("GET", id=42, custom_flag=True)

        assert [req["method"] for req in aclient.sent_requests] == ["POST", "GET", "PUT", "PATCH", "DELETE", "GET"]
        assert aclient.sent_requests[0]["endpoint"] == "send_v31"
        assert aclient.sent_requests[0]["headers"] == {"X-Test": "1"}
        assert aclient.sent_requests[1]["filters"] == {"Limit": 5}
        assert aclient.sent_requests[-1]["kwargs"] == {"custom_flag": True}

        mc = MockMailjetClient(default_status=201)
        res_proxy = await mc.contact.create(
            data=types.MappingProxyType({"Email": "proxy@example.com"}),
            id=11,
            action_id="manage",
            headers={"X-H": "v"},
            timeout=5,
        )
        assert res_proxy.status_code == 201
        assert type(mc.sent_requests[-1]["data"]) is dict
        assert mc.sent_requests[-1] == {
            "endpoint": "contact",
            "method": "POST",
            "id": 11,
            "action_id": "manage",
            "data": {"Email": "proxy@example.com"},
            "filters": None,
            "headers": {"X-H": "v"},
            "kwargs": {"timeout": 5},
        }

        await mc.contact.get(id=1, filters={"Limit": 2}, action_id="a", headers={"H": "1"}, timeout=3)
        assert mc.sent_requests[-1]["method"] == "GET"
        await mc.contact.update(id=2, data={"k": "v"}, action_id="b", headers={"H": "2"}, timeout=4)
        assert mc.sent_requests[-1]["method"] == "PUT"
        await mc.contact.patch(id=3, data={"k": "p"}, action_id="c", headers={"H": "3"}, timeout=5)
        assert mc.sent_requests[-1]["method"] == "PATCH"
        await mc.contact.delete(id=4, action_id="d", timeout=6)
        assert mc.sent_requests[-1]["method"] == "DELETE"
        res_call = await mc.contact(
            method="PUT",
            id=5,
            data={"x": 1},
            filters={"f": 2},
            action_id="e",
            headers={"H": "9"},
            timeout=7,
        )
        assert res_call.status_code == 201
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
        await mc.aclose()

    asyncio.run(_run())


def test_mock_response_await_json_isolation_and_error_mapping_async() -> None:
    """Verify MockResponse.__await__, json() isolation, and raise_for_status() HTTP error mapping."""

    async def _run() -> None:
        resp = MockResponse(status_code=202, _payload={"Count": 1, "Total": 1, "Data": [{"ID": 10}]}, text="ok")
        awaited = await resp
        assert awaited is resp

        first_copy = awaited.json()
        first_copy["Count"] = 999
        first_copy["Injected"] = True
        second_copy = awaited.json()
        assert second_copy["Count"] == 1
        assert "Injected" not in second_copy

        async with MockMailjetClient(default_status=200) as ok_client:
            (await ok_client.contact.get()).raise_for_status()
        async with MockMailjetClient(default_status=399) as edge_client:
            (await edge_client.contact.get()).raise_for_status()

        status_map: list[tuple[int, type[MailjetApiError]]] = [
            (400, ValidationError),
            (401, MailjetAuthError),
            (403, MailjetAuthError),
            (404, DoesNotExistError),
            (429, ApiRateLimitError),
            (500, MailjetApiError),
            (503, MailjetApiError),
        ]
        for status_code, expected_exc in status_map:
            async with MockMailjetClient(default_status=status_code) as err_client:
                err_resp = await err_client.contact.get()
                with pytest.raises(expected_exc) as exc_info:
                    err_resp.raise_for_status()
                assert exc_info.value.status_code == status_code
                assert isinstance(exc_info.value.__cause__, RuntimeError)
                assert str(exc_info.value.__cause__) == f"Mock HTTP {status_code}"

    asyncio.run(_run())


def test_mock_stream_async_iteration_and_ping_await() -> None:
    """Cover async for on MockEndpoint.stream() and _MockStreamIterator, plus await mock.ping()."""

    async def _run() -> None:
        non_empty_it = _MockStreamIterator(({"ID": 1}, {"ID": 2}))
        assert aiter(non_empty_it) is non_empty_it
        collected = [item async for item in non_empty_it]
        assert collected == [{"ID": 1}, {"ID": 2}]
        with pytest.raises(StopAsyncIteration):
            await anext(non_empty_it)

        async with MockMailjetClient(default_status=200) as aclient:
            stream_items = [
                item
                async for item in aclient.contact.stream(
                    id=7,
                    filters={"Limit": 5},
                    action_id="contactslist",
                    chunk_size=50,
                    method="GET",
                    max_items=10,
                    timeout=2,
                )
            ]
            assert stream_items == []
            assert aclient.sent_requests[-1] == {
                "endpoint": "contact",
                "method": "GET",
                "id": 7,
                "action_id": "contactslist",
                "data": None,
                "filters": {"Limit": 5},
                "kwargs": {"timeout": 2},
            }

            ping_200 = await aclient.ping(timeout=5)
            assert ping_200 is True

        ping_399 = await MockMailjetClient(default_status=399).ping()
        ping_400 = await MockMailjetClient(default_status=400).ping()
        ping_500 = await MockMailjetClient(default_status=500).ping()
        assert ping_399 is True
        assert ping_400 is False
        assert ping_500 is False

    asyncio.run(_run())


def test_mock_endpoint_async_validation_guards_and_context_exception() -> None:
    """Cover invalid ID guards, stream() errors, _hidden AttributeError, and async with exception safety."""

    async def _run() -> None:
        async with MockMailjetClient() as aclient:
            invalid_ids: tuple[Any, ...] = ("", "   ", None, True, False)
            for bad_id in invalid_ids:
                with pytest.raises(
                    ValueError, match=r"MockEndpoint\.patch\(\) requires a non-empty, non-boolean resource 'id'\."
                ):
                    await aclient.contact.patch(bad_id, data={"Name": "X"})
                with pytest.raises(
                    ValueError, match=r"MockEndpoint\.delete\(\) requires a non-empty, non-boolean resource 'id'\."
                ):
                    await aclient.contact.delete(bad_id)

            assert (await aclient.contact.patch(0, data={"Name": "Zero"})).status_code == 200
            assert (await aclient.contact.delete("0")).status_code == 200

            with pytest.raises(ValueError, match="stream\\(\\) is designed for GET requests only"):
                aclient.contact.stream(method="POST")
            for bad_chunk in (0, -1, True, 1001):
                with pytest.raises(ValueError, match="chunk_size"):
                    aclient.contact.stream(chunk_size=bad_chunk)
            for bad_max_items in (-1, True):
                with pytest.raises(ValueError, match="max_items"):
                    aclient.contact.stream(max_items=bad_max_items)

            with pytest.raises(AttributeError, match="'MockMailjetClient' object has no attribute '_hidden'"):
                _ = aclient._hidden

        err_client = MockMailjetClient()
        with pytest.raises(RuntimeError, match="async boom"):
            async with err_client:
                await err_client.contact.get(id=1)
                raise RuntimeError("async boom")
        assert len(err_client.sent_requests) == 1

    asyncio.run(_run())
