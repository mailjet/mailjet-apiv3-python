"""Synchronous unit tests for mailjet_rest.testing in-memory test doubles."""

from __future__ import annotations

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
    _MockPingResult,
    _MockStreamIterator,
)


def test_mock_mailjet_client_direct_create_and_slots() -> None:
    """MockMailjetClient supports direct create(data=...), custom status, and slotted layout."""
    client = MockMailjetClient()
    assert not hasattr(client, "__dict__")

    payload: dict[str, Any] = {"Messages": [{"Subject": "Direct MOD-03 test"}]}
    res = client.create(data=payload)
    assert res == {"Status": "success", "StatusCode": 200}
    assert client.sent_requests == [{"data": payload}]

    custom = MockMailjetClient(default_status=202)
    assert custom.create(data={"ping": True}) == {"Status": "success", "StatusCode": 202}


def test_mock_mailjet_client_endpoints_and_context_managers() -> None:
    """MockMailjetClient records endpoint CRUD calls, sync context managers, and HTTP errors."""
    with MockMailjetClient() as mock_client:
        endpoint = mock_client.send_v31
        assert isinstance(endpoint, MockEndpoint)
        assert not hasattr(endpoint, "__dict__")

        create_resp = endpoint.create(data={"Messages": [{"Subject": "Hi"}]}, headers={"X-Test": "1"})
        assert isinstance(create_resp, MockResponse)
        assert not hasattr(create_resp, "__dict__")
        assert create_resp.status_code == 200
        assert create_resp.json()["Status"] == "success"
        create_resp.raise_for_status()

        mock_client.contact.get(id=42, filters={"Limit": 5})
        mock_client.contact.update(id=42, data={"Name": "Updated"})
        mock_client.contact.patch(id=42, data={"Name": "Patched"})
        mock_client.contact.delete(id=42)
        mock_client.contact("GET", id=42, custom_flag=True)

        with pytest.raises(AttributeError, match="no attribute '_secret'"):
            _ = mock_client._secret  # ruff: ignore[private-member-access]

    assert [req["method"] for req in mock_client.sent_requests] == ["POST", "GET", "PUT", "PATCH", "DELETE", "GET"]
    assert mock_client.sent_requests[0]["endpoint"] == "send_v31"
    assert mock_client.sent_requests[0]["headers"] == {"X-Test": "1"}
    assert mock_client.sent_requests[1]["filters"] == {"Limit": 5}
    assert mock_client.sent_requests[-1]["kwargs"] == {"custom_flag": True}

    with pytest.raises(ValidationError):
        MockResponse(status_code=400, text="bad payload").raise_for_status()
    with pytest.raises(MailjetApiError):
        MockResponse(status_code=503, text="unavailable").raise_for_status()


def test_testing_module_mock_client_endpoint_and_response_contracts() -> None:
    """Kill surviving mutants in mailjet_rest.testing (sync contracts)."""
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


def test_mock_endpoint_parameter_forwarding() -> None:
    """Verify MockEndpoint parameter forwarding across every HTTP helper."""
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


def test_mock_response_json_isolation_and_error_mapping() -> None:
    """MockResponse.json() returns an isolated shallow copy and raise_for_status() maps HTTP codes."""
    resp = MockResponse(status_code=200, _payload={"Count": 1, "Total": 1, "Data": [{"ID": 10}]})
    first_copy = resp.json()
    first_copy["Count"] = 999
    first_copy["Injected"] = True
    second_copy = resp.json()
    assert second_copy["Count"] == 1
    assert "Injected" not in second_copy

    MockResponse(status_code=200).raise_for_status()
    MockResponse(status_code=399).raise_for_status()

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
        err_resp = MockResponse(status_code=status_code, text=f"http-{status_code}")
        with pytest.raises(expected_exc) as exc_info:
            err_resp.raise_for_status()
        assert exc_info.value.status_code == status_code
        assert isinstance(exc_info.value.__cause__, RuntimeError)
        assert str(exc_info.value.__cause__) == f"Mock HTTP {status_code}"


def test_mock_stream_iterator_and_ping_result_contracts() -> None:
    """Cover _MockStreamIterator sync iteration, MockEndpoint.stream(), and _MockPingResult semantics."""
    non_empty_it = _MockStreamIterator(({"ID": 1}, {"ID": 2}))
    assert iter(non_empty_it) is non_empty_it
    assert list(non_empty_it) == [{"ID": 1}, {"ID": 2}]
    with pytest.raises(StopIteration):
        next(non_empty_it)

    empty_it = _MockStreamIterator()
    assert list(empty_it) == []

    mc = MockMailjetClient(default_status=200)
    streamed = mc.contact.stream(
        id=7,
        filters={"Limit": 5},
        action_id="contactslist",
        chunk_size=50,
        method="GET",
        max_items=10,
        timeout=2,
    )
    assert isinstance(streamed, _MockStreamIterator)
    assert list(streamed) == []
    assert mc.sent_requests[-1] == {
        "endpoint": "contact",
        "method": "GET",
        "id": 7,
        "action_id": "contactslist",
        "data": None,
        "filters": {"Limit": 5},
        "kwargs": {"timeout": 2},
    }

    ping_ok = mc.ping(timeout=5)
    ping_edge = MockMailjetClient(default_status=399).ping()
    ping_err = MockMailjetClient(default_status=400).ping()
    ping_500 = MockMailjetClient(default_status=500).ping()

    assert isinstance(ping_ok, _MockPingResult)
    assert bool(ping_ok) is True
    assert bool(ping_edge) is True
    assert bool(ping_err) is False
    assert bool(ping_500) is False

    assert ping_ok == True  # noqa: E712
    assert ping_ok != False  # noqa: E712
    assert ping_err == False  # noqa: E712
    assert ping_err != True  # noqa: E712
    assert ping_ok == _MockPingResult(True)
    assert ping_ok != _MockPingResult(False)
    assert ping_ok.__eq__("yes") is NotImplemented
    assert ping_ok != "yes"
    assert ping_ok != 1
    assert hash(ping_ok) == hash(True)
    assert hash(ping_err) == hash(False)
    assert repr(ping_ok) == "True"
    assert repr(ping_err) == "False"


def test_mock_endpoint_validation_guards_and_close_semantics() -> None:
    """Cover invalid ID guards on patch/delete, stream() arg errors, _hidden AttributeError, and close()."""
    mc = MockMailjetClient()
    invalid_ids: tuple[Any, ...] = ("", "   ", None, True, False)
    for bad_id in invalid_ids:
        with pytest.raises(
            ValueError, match=r"MockEndpoint\.patch\(\) requires a non-empty, non-boolean resource 'id'\."
        ):
            mc.contact.patch(bad_id, data={"Name": "X"})
        with pytest.raises(
            ValueError, match=r"MockEndpoint\.delete\(\) requires a non-empty, non-boolean resource 'id'\."
        ):
            mc.contact.delete(bad_id)

    # Numeric zero and string "0" remain valid identifiers
    assert mc.contact.patch(0, data={"Name": "Zero"}).status_code == 200
    assert mc.contact.delete("0").status_code == 200

    with pytest.raises(ValueError, match="stream\\(\\) is designed for GET requests only"):
        mc.contact.stream(method="POST")
    for bad_chunk in (0, -1, True, 1001):
        with pytest.raises(ValueError, match="chunk_size"):
            mc.contact.stream(chunk_size=bad_chunk)
    for bad_max_items in (-1, True):
        with pytest.raises(ValueError, match="max_items"):
            mc.contact.stream(max_items=bad_max_items)

    with pytest.raises(AttributeError, match="'MockMailjetClient' object has no attribute '_hidden'"):
        _ = mc._hidden

    mc.close()

    with pytest.raises(RuntimeError, match="boom"), MockMailjetClient() as err_mc:
        err_mc.contact.get(id=1)
        raise RuntimeError("boom")
    assert len(err_mc.sent_requests) == 1
