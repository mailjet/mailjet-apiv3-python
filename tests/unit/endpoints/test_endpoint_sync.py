"""Unit tests for synchronous endpoint operations, routing, casting, and stream pagination (Endpoint)."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import parse_qs

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
import responses

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.errors import MailjetApiError


# ==========================================
# 1. Stream Pagination & Filter Normalization
# ==========================================


@pytest.mark.parametrize("offset", [0, 10])
@pytest.mark.parametrize("size", [3, 4])
@responses.activate
def test_stream_with_page_local_total(offset: int, size: int) -> None:
    """REST responses report Total for the current page, not the whole collection."""
    data = [{"ID": index} for index in range(offset, offset + size)]
    for start in range(0, size + 1, 2):
        page = data[start : start + 2]
        responses.add(
            responses.GET,
            "https://api.mailjet.com/v3/REST/contact",
            match=[responses.matchers.query_param_matcher({"Offset": offset + start, "Limit": 2})],
            json={"Count": len(page), "Total": len(page), "Data": page},
        )

    with Client(auth=("test", "test"), version="v3") as client:
        assert list(client.contact.stream(filters={"Offset": offset}, chunk_size=2)) == data
    assert len(responses.calls) == size // 2 + 1


@responses.activate
def test_stream_empty_collection_exits_immediately() -> None:
    """Ensure an empty collection returns an empty generator after a single request."""
    responses.add(
        responses.GET,
        "https://api.mailjet.com/v3/REST/contact",
        match=[responses.matchers.query_param_matcher({"Offset": 0, "Limit": 10})],
        json={"Count": 0, "Total": 0, "Data": []},
    )

    with Client(auth=("test", "test"), version="v3") as client:
        assert list(client.contact.stream(chunk_size=10)) == []

    assert len(responses.calls) == 1


def test_stream_chunk_size_max_limit_rejection() -> None:
    """Ensure chunk_size values exceeding Mailjet's API limit (1000) are rejected."""
    client = Client(auth=("key", "secret"))

    with pytest.raises(ValueError, match=r"exceeds Mailjet's maximum Limit of 1000"):
        next(client.contact.stream(chunk_size=1001))

    with pytest.raises(ValueError, match=r"exceeds Mailjet's maximum Limit of 1000"):
        next(client.contact.stream(chunk_size=5000))


def test_stream_filter_strips_both_limit_casings() -> None:
    """Verify both 'limit' and 'Limit' in input filters are cleanly normalized to chunk_size."""
    filters = {"limit": 50, "Limit": 100, "Offset": 0}
    clean_filters, offset = Endpoint._normalize_stream_filters(filters, chunk_size=500)

    assert offset == 0
    assert clean_filters["Limit"] == 500
    assert "limit" not in clean_filters


def test_stream_lazy_pagination(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that .stream() automatically paginates and yields individual records."""
    client = Client(auth=("a", "b"))

    call_count = 0

    def mock_paginated_response(**kwargs: Any) -> requests.Response:
        nonlocal call_count
        resp = requests.Response()
        resp.status_code = 200

        if call_count == 0:
            resp._content = b'{"Total": 3, "Data": [{"id": 1}, {"id": 2}]}'
        elif call_count == 1:
            resp._content = b'{"Total": 3, "Data": [{"id": 3}]}'
        else:
            resp._content = b'{"Total": 3, "Data": []}'

        call_count += 1
        return resp

    monkeypatch.setattr(client.session, "request", mock_paginated_response)

    items = list(client.contact.stream(chunk_size=2))

    assert len(items) == 3
    assert items[0]["id"] == 1
    assert items[2]["id"] == 3
    # With early break optimization, it stops at the exact chunk boundary
    assert call_count == 2


def test_stream_bool_negative_max_items_and_bad_json(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify HIGH-04 bool/negative guards, max_items limit, and MailjetApiError on invalid JSON."""
    with Client(auth=("pub", "priv")) as client:
        with pytest.raises(ValueError, match="strictly positive integer"):
            next(client.contact.stream(chunk_size=True))  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="Offset filter must be an integer"):
            next(client.contact.stream(filters={"Offset": True}))

        with pytest.raises(ValueError, match="non-negative integer"):
            next(client.contact.stream(filters={"Offset": -1}))

        with pytest.raises(ValueError, match="max_items"):
            next(client.contact.stream(max_items=True))  # type: ignore[arg-type]

        with pytest.raises(ValueError, match="max_items"):
            next(client.contact.stream(max_items=-5))

        calls = 0

        def mock_request(method: str, url: str, **kwargs: object) -> MagicMock:
            nonlocal calls
            calls += 1
            resp = MagicMock()
            resp.status_code = 200
            resp.text = '{"Data": []}'
            if calls == 1:
                resp.json.return_value = {"Data": [{"ID": 1}, {"ID": 2}]}
            elif calls == 2:
                resp.json.return_value = {"Data": [{"ID": 3}, {"ID": 4}]}
            return resp

        monkeypatch.setattr(client.session, "request", mock_request)

        # max_items == 0 performs zero HTTP calls
        assert list(client.contact.stream(chunk_size=2, max_items=0)) == []
        assert calls == 0

        # max_items == 3 stops cleanly after item 3
        items = list(client.contact.stream(chunk_size=2, max_items=3))
        assert [item["ID"] for item in items] == [1, 2, 3]
        assert calls == 2

        # Malformed JSON raises MailjetApiError
        bad_json_resp = MagicMock()
        bad_json_resp.status_code = 502
        bad_json_resp.text = "bad gateway"
        bad_json_resp.json.side_effect = ValueError("No JSON")
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=bad_json_resp))
        with pytest.raises(MailjetApiError, match="Malformed JSON"):
            next(client.contact.stream())

        # Non-dict JSON body raises MailjetApiError
        list_resp = MagicMock()
        list_resp.status_code = 200
        list_resp.text = "[]"
        list_resp.json.return_value = []
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=list_resp))
        with pytest.raises(MailjetApiError, match="Expected JSON object"):
            next(client.contact.stream())

        # Non-list 'Data' raises MailjetApiError
        bad_data_resp = MagicMock()
        bad_data_resp.status_code = 200
        bad_data_resp.text = '{"Data": 123}'
        bad_data_resp.json.return_value = {"Data": 123}
        monkeypatch.setattr(client.session, "request", MagicMock(return_value=bad_data_resp))
        with pytest.raises(MailjetApiError, match="Expected 'Data' list"):
            next(client.contact.stream())


# ==========================================
# 2. Synchronous CRUD, Routing & Casting Tests
# ==========================================


@responses.activate
def test_endpoint_create_deprecated_args(client_offline: Client) -> None:
    """__call__ warnings on create."""
    responses.add(responses.POST, "https://api.mailjet.com/v3/REST/contact", status=201, json={})

    with pytest.warns(DeprecationWarning, match="'ensure_ascii' and 'data_encoding' are deprecated"):
        client_offline.contact.create(data={"Email": "test@test.com"}, ensure_ascii=False)


@responses.activate
def test_endpoint_update_deprecated_args(client_offline: Client) -> None:
    """Update method warnings."""
    responses.add(responses.PUT, "https://api.mailjet.com/v3/REST/contact/123", status=200, json={})

    with pytest.warns(DeprecationWarning, match="'ensure_ascii' and 'data_encoding' are deprecated"):
        client_offline.contact.update(id="123", data={"Name": "New"}, data_encoding="utf-8")


@responses.activate
def test_endpoint_delete(client_offline: Client) -> None:
    """Delete method."""
    responses.add(responses.DELETE, "https://api.mailjet.com/v3/REST/contact/123", status=204)
    res = client_offline.contact.delete(id="123")
    assert res.status_code == 204


@responses.activate
def test_endpoint_methods_no_id(client_offline: Client) -> None:
    responses.add(responses.GET, "https://api.mailjet.com/v3/REST/contact", json={"data": []})
    res = client_offline.contact.get()
    assert res.status_code == 200


@responses.activate
def test_endpoint_create_no_data(client_offline: Client) -> None:
    responses.add(responses.POST, "https://api.mailjet.com/v3/REST/contact", json={})
    res = client_offline.contact.create()
    assert res.status_code == 200


@responses.activate
def test_endpoint_update_no_id(client_offline: Client) -> None:
    # Add the trailing slash to the mock URL, as the router appends
    # "/{id}" even if id is empty, resulting in "contact/"
    responses.add(responses.PUT, "https://api.mailjet.com/v3/REST/contact/", json={"success": True})

    # Pass an empty string to satisfy the method signature while testing falsy ID routing
    res = client_offline.contact.update(id="", data={"Name": "New"})
    assert res.status_code == 200


@responses.activate
def test_endpoint_action_id_resolution(client_offline: Client) -> None:
    responses.add(responses.GET, "https://api.mailjet.com/v3/DATA/contactslist/123/CSVData/text:plain", json={})
    # This specifically triggers the 'CSVData' suffix logic
    client_offline.contactslist_csvdata.get(id="123")


def test_endpoint_missing_uri_kwargs(client_offline: Client) -> None:
    """Coverage: Force ValueError for missing path parameters in route templates."""
    with pytest.raises(ValueError, match="requires an 'id' parameter"):
        client_offline.contact_getcontactslists._build_url()

    with pytest.raises(ValueError, match="requires an 'action_id' parameter"):
        client_offline.template_content_by_type._build_url(id_val=1)


def test_endpoint_dynamic_action_id_fallback(client_offline: Client) -> None:
    """Coverage: Test multi-part action_id formatting in _build_url fallback logic."""
    # 'contact_custom' is a multi-part name not in ROUTE_MAP
    # Shift logic triggers `action_id = f"{safe_action}/{action_id}"`
    url = client_offline.contact_custom._build_url(id_val=123, action_id=456)
    assert "REST/contact/123/custom/456" in url


def test_endpoint_dynamic_data_routing(client_offline: Client) -> None:
    """Coverage: Test dynamic data_ route building."""
    url = client_offline.data_testroute._build_url()
    assert "v3/data/testroute" in url


def test_endpoint_init_action_parts_casing_and_hyphenation() -> None:
    """Verify camelCase-to-kebab conversion and case-preservation in __init__."""
    client = Client(auth=("key", "secret"))

    # 1. Single camelCase sub-action
    ep1 = Endpoint(client, "customResource_linkClick")
    assert ep1._resource_lower == "customresource"
    assert ep1._action_parts == ["customresource", "link-click"]

    # 2. Leading uppercase on sub-action (lstrip("-") branch)
    ep2 = Endpoint(client, "customResource_LinkClick")
    assert ep2._action_parts == ["customresource", "link-click"]

    # 3. Multiple sub-action parts with mixed cases
    ep3 = Endpoint(client, "myResource_firstAction_secondActionName")
    assert ep3._resource_lower == "myresource"
    assert ep3._action_parts == ["myresource", "first-action", "second-action-name"]

    # 4. Purely lowercased resource without sub-actions
    ep4 = Endpoint(client, "simpleresource")
    assert ep4._resource_lower == "simpleresource"
    assert ep4._action_parts == ["simpleresource"]


def test_endpoint_dynamic_subaction_routing_branches() -> None:
    """Cover lines 123-132: dynamic fallback with id_val and action_id permutations."""
    client = Client(auth=("key", "secret"), version="v3")

    # Branch A: id_val is None -> action_id shifts to primary ID position
    url_shifted = client.customResource_someAction._build_url(action_id=456)
    assert url_shifted == "https://api.mailjet.com/v3/REST/customresource/456/some-action"

    # Branch B: id_val provided and action_id is None
    url_id_only = client.customResource_someAction._build_url(id_val=123)
    assert url_id_only == "https://api.mailjet.com/v3/REST/customresource/123/some-action"

    # Branch C: both id_val and action_id provided -> composite action path
    url_both = client.customResource_someAction._build_url(id_val=123, action_id=456)
    assert url_both == "https://api.mailjet.com/v3/REST/customresource/123/some-action/456"

    # Branch D: neither provided
    url_none = client.customResource_someAction._build_url()
    assert url_none == "https://api.mailjet.com/v3/REST/customresource/some-action"


def test_endpoint_dynamic_data_with_action_id() -> None:
    """Cover line 121: unmapped data_ prefix with an action_id passed."""
    client = Client(auth=("key", "secret"), version="v1")
    url = client.data_custom_path._build_url(action_id="sub_token")
    assert url == "https://api.mailjet.com/v1/data/custom/path/sub_token"


def test_endpoint_stream_input_validation() -> None:
    """Cover stream method and chunk_size guards (use raw string to prevent SyntaxWarning)."""
    client = Client(auth=("key", "secret"))

    # Invalid HTTP method - raw string r"..." eliminates Python 3.12 SyntaxWarning
    with pytest.raises(ValueError, match=r"stream\(\) is designed for GET requests only"):
        next(client.contact.stream(method="POST"))

    # Invalid chunk_size <= 0
    with pytest.raises(ValueError, match=r"chunk_size must be a strictly positive integer"):
        next(client.contact.stream(chunk_size=0))

    # Invalid Offset type
    with pytest.raises(ValueError, match=r"stream\(\) Offset filter must be an integer"):
        next(client.contact.stream(filters={"offset": "invalid_offset"}))


def test_endpoint_call_deprecated_encoding_scalar_payload(monkeypatch: pytest.MonkeyPatch) -> None:
    """Cover branch 252->257: ensure_ascii/data_encoding with non-dict/list payload."""
    client = Client(auth=("key", "secret"))
    endpoint = client.contact

    def mock_api_call(self: object, *args: object, **kwargs: object) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(Client, "api_call", mock_api_call)

    with pytest.warns(DeprecationWarning, match="'ensure_ascii' and 'data_encoding' are deprecated"):
        # Passing string data instead of dict/list tests the branch fallback
        endpoint(method="POST", data="plain text data", ensure_ascii=True)


def test_stream_filter_normalization_and_snapshot_isolation(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify stream handles lowercase offset/limit and preserves filter immutability."""
    client = Client(auth=("key", "secret"))
    captured_filters: list[dict[str, object]] = []

    def mock_get(self: Endpoint, *args: object, **kwargs: object) -> requests.Response:
        filters = kwargs.get("filters", {})
        assert isinstance(filters, dict)
        captured_filters.append(filters)
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"Total": 1, "Data": [{"id": 100}]}'
        return resp

    # Patch Endpoint class, not the slotted client.contact instance
    monkeypatch.setattr(Endpoint, "get", mock_get)

    initial_filters = {"offset": "20", "limit": "5", "Custom": "KeepMe"}
    items = list(client.contact.stream(filters=initial_filters, chunk_size=50))

    assert len(items) == 1
    assert captured_filters[0]["Offset"] == 20
    assert captured_filters[0]["Limit"] == 50
    assert "offset" not in captured_filters[0]
    assert "limit" not in captured_filters[0]
    assert captured_filters[0]["Custom"] == "KeepMe"


def test_endpoint_cast_query_param_scalar_and_collections() -> None:
    """Validate _cast_query_param against all supported Python types."""
    # Boolean casting
    assert Endpoint._cast_query_param(True, ["true"]) is True
    assert Endpoint._cast_query_param(True, ["1"]) is True
    assert Endpoint._cast_query_param(True, "yes") is True
    assert Endpoint._cast_query_param(True, ["false"]) is False
    assert Endpoint._cast_query_param(True, ["0"]) is False

    # Numeric casting
    assert Endpoint._cast_query_param(0, ["42"]) == 42
    assert Endpoint._cast_query_param(0, "42") == 42
    assert Endpoint._cast_query_param(0.0, ["3.14"]) == 3.14
    assert Endpoint._cast_query_param(0.0, "3.14") == 3.14

    # Collection casting
    assert Endpoint._cast_query_param([], ["a", "b"]) == ["a", "b"]
    assert Endpoint._cast_query_param((), ["a", "b"]) == ("a", "b")
    assert Endpoint._cast_query_param(set(), ["a", "b"]) == {"a", "b"}

    # String fallback
    assert Endpoint._cast_query_param("ref", ["alpha"]) == "alpha"
    assert Endpoint._cast_query_param("ref", "alpha") == "alpha"

    # Empty collection fallbacks
    assert Endpoint._cast_query_param(True, []) is False
    assert Endpoint._cast_query_param(0, []) == 0
    assert Endpoint._cast_query_param(0.0, []) == 0.0
    assert Endpoint._cast_query_param([], []) == []


def test_stream_with_parse_qs_multidict(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ensure stream() seamlessly consumes parse_qs output without TypeError."""
    client = Client(auth=("key", "secret"))
    captured_offsets: list[int] = []

    def mock_get(self: Endpoint, *args: object, **kwargs: object) -> requests.Response:
        filters = kwargs.get("filters", {})
        assert isinstance(filters, dict)
        captured_offsets.append(filters["Offset"])

        resp = requests.Response()
        resp.status_code = 200
        # For offset=10 (with 3 items across offsets 10-12), the database Total is 13
        if filters["Offset"] == 10:
            resp._content = b'{"Total": 13, "Data": [{"id": 1}, {"id": 2}]}'
        else:
            resp._content = b'{"Total": 13, "Data": [{"id": 3}]}'
        return resp

    monkeypatch.setattr(Endpoint, "get", mock_get)

    raw_query = parse_qs("offset=10&limit=2")
    items = list(client.contact.stream(filters=raw_query, chunk_size=2))

    assert len(items) == 3
    assert captured_offsets == [10, 12]


# ==========================================
# 3. Repr, Update Forwarding & Mutation Coverage
# ==========================================


def test_sync_endpoint_repr_and_update(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify synchronous Endpoint repr() and PUT update execution."""
    with Client(auth=("key", "secret"), version="v3") as sync_client:
        sync_ep: Endpoint = sync_client.contact
        assert repr(sync_ep) == "<Endpoint name='contact'>"
        captured: dict[str, Any] = {}

        def fake_sync_request(**kwargs: Any) -> Any:
            captured.update(kwargs)
            return type("Resp", (), {"status_code": 200, "raise_for_status": lambda _s=None: None})()

        monkeypatch.setattr(sync_client.session, "request", fake_sync_request)
        sync_resp = sync_ep.update(id=42, data={"Name": "SyncUpdated"})
        assert sync_resp.status_code == 200
        assert captured["method"] == "PUT"
        assert captured["url"].endswith("/v3/REST/contact/42")


def test_endpoint_contracts_stream_errors_routing_and_cast(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Endpoint CRUD forwarding, routing, _parse_stream_page errors, and _cast_query_param."""
    captured: list[dict[str, object]] = []

    def fake_api_call(
        self: Client,
        method: str,
        url: str,
        *,
        headers: object = None,
        data: object = None,
        filters: object = None,
        timeout: object = None,
        action_id: object = None,
        **kwargs: object,
    ) -> requests.Response:
        captured.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "data": data,
                "filters": filters,
                "timeout": timeout,
                "action_id": action_id,
                "kwargs": kwargs,
            }
        )
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(Client, "api_call", fake_api_call)

    with Client(auth=("pub", "priv"), config=Config(api_url="https://api.mailjet.com/", version="v3")) as c:
        c.contact.create(
            id=11,
            action_id=22,
            data={"Email": "u@example.com"},
            headers={"X-C": "1"},
            filters={"Show": "all"},
            timeout=9.0,
        )
        assert len(captured) == 1
        assert captured[0]["method"] == "POST"
        assert captured[0]["url"] == "https://api.mailjet.com/v3/REST/contact/11/22"
        assert captured[0]["headers"] == {"Content-Type": "application/json", "X-C": "1"}
        assert captured[0]["filters"] == {"Show": "all"}
        assert captured[0]["timeout"] == 9.0

        c.contact.update(
            id=33,
            action_id=44,
            data={"Name": "Alice"},
            headers={"X-U": "2"},
            filters={"F": "1"},
            timeout=8.0,
        )
        assert len(captured) == 2
        assert captured[1]["method"] == "PUT"
        assert captured[1]["url"] == "https://api.mailjet.com/v3/REST/contact/33/44"
        assert captured[1]["headers"] == {"Content-Type": "application/json", "X-U": "2"}
        assert captured[1]["filters"] == {"F": "1"}
        assert captured[1]["timeout"] == 8.0

        c.contact.delete(id=55, action_id=66, timeout=7.0)
        assert len(captured) == 3
        assert captured[2]["method"] == "DELETE"
        assert captured[2]["url"] == "https://api.mailjet.com/v3/REST/contact/55/66"
        assert captured[2]["timeout"] == 7.0

        with pytest.warns(DeprecationWarning) as tpl_warn:
            tpl_url = c.templates._build_url()
        assert str(tpl_warn[0].message) == "Mailjet API Ambiguity: Email API (v3) uses singular '/template'"
        assert tpl_url == "https://api.mailjet.com/v3/REST/templates"

        assert c.send._build_url() == "https://api.mailjet.com/v3/send"
        assert (
            c.contactslist_csverror._build_url(id_val=77)
            == "https://api.mailjet.com/v3/DATA/contactslist/77/CSVError/text:csv"
        )
        assert c.contactslist_csvdata._build_headers()["Content-Type"] == "text/plain"

    # _parse_stream_page exact status_code/body slicing & AttributeError handling
    no_attr_resp = SimpleNamespace(json=MagicMock(side_effect=AttributeError("missing")), status_code=None, text=None)
    with pytest.raises(MailjetApiError) as err1:
        Endpoint._parse_stream_page(no_attr_resp)
    assert str(err1.value) == "Malformed JSON body returned during stream() pagination."
    assert err1.value.status_code == 0
    assert err1.value.response_body == ""

    long_resp = SimpleNamespace(status_code=504, text="x" * 700, json=lambda: [1, 2])
    with pytest.raises(MailjetApiError) as err2:
        Endpoint._parse_stream_page(long_resp)
    assert str(err2.value) == "Expected JSON object in stream() response."
    assert err2.value.status_code == 504
    assert len(err2.value.response_body or "") == 500

    empty_data_resp = SimpleNamespace(status_code=200, text="{}", json=dict)
    assert Endpoint._parse_stream_page(empty_data_resp) == []

    # _validate_stream_args exact messages + chunk_size=1 + max_items=1
    with Client(auth=("pub", "priv")) as c2:
        with pytest.raises(ValueError) as cs_exc:
            next(c2.contact.stream(chunk_size=0))
        assert str(cs_exc.value) == "stream() chunk_size must be a strictly positive integer."

        with pytest.raises(ValueError) as mi_exc:
            next(c2.contact.stream(max_items=-1))
        assert str(mi_exc.value) == "stream() max_items must be a non-negative integer or None."

        monkeypatch.setattr(
            Endpoint,
            "get",
            lambda _self, **_kw: SimpleNamespace(status_code=200, text="{}", json=lambda: {"Data": [{"ID": 9}]}),
        )
        assert list(c2.contact.stream(chunk_size=1, max_items=1)) == [{"ID": 9}]

    # _cast_query_param full truthiness, empty collection type, and bool numeric rejection
    assert Endpoint._cast_query_param(orig_ref=True, raw_values="T") is True
    assert Endpoint._cast_query_param(orig_ref=True, raw_values="false") is False
    empty_str = Endpoint._cast_query_param("s", [])
    assert empty_str == "" and isinstance(empty_str, str)
    with pytest.raises(TypeError) as bool_num_exc:
        Endpoint._cast_query_param(orig_ref=0, raw_values=True)
    assert str(bool_num_exc.value) == "Boolean value is not a valid numeric query parameter."


def test_endpoint_update_forward_all_args() -> None:
    """Kill survived argument-forwarding mutants in Endpoint.update."""
    sync_client = MagicMock()
    sync_client.config.api_url = "https://api.mailjet.com"
    sync_client.config.version = "v3"
    ep = Endpoint(sync_client, "contact")

    with pytest.warns(DeprecationWarning, match="deprecated"):
        ep.update(
            id=7,
            data={"Name": "Updated"},
            action_id="sub",
            headers={"X-Test": "1"},
            ensure_ascii=False,
            data_encoding="utf-8",
            timeout=5,
        )
    sync_client.api_call.assert_called_once()
    call_kw = sync_client.api_call.call_args.kwargs
    assert call_kw["method"] == "PUT"
    assert "/v3/REST/contact/7/sub" in call_kw["url"]
    assert call_kw["headers"]["X-Test"] == "1"
    assert call_kw["timeout"] == 5


def test_endpoint_mutants() -> None:
    """Kill surviving mutants across Endpoint.__call__, get, stream, and update."""
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

    # Endpoint.update exact forwarding including ensure_ascii & data_encoding
    with patch.object(Endpoint, "__call__", return_value=MagicMock()) as mock_ep_call:
        ep.update(
            id=3, data={"Name": "N"}, action_id="act", headers={"X-P": "1"}, ensure_ascii=True, data_encoding="latin-1"
        )
    assert mock_ep_call.call_args.kwargs == {
        "method": "PUT",
        "id": 3,
        "data": {"Name": "N"},
        "action_id": "act",
        "headers": {"X-P": "1"},
        "ensure_ascii": True,
        "data_encoding": "latin-1",
    }
