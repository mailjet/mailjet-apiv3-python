from urllib.parse import parse_qs
import pytest
import requests
import responses

from mailjet_rest.client import Client
from mailjet_rest.endpoint import Endpoint


@pytest.fixture
def client_offline() -> Client:
    """Local fixture to provide a basic Client instance."""
    return Client(auth=("test", "test"), version="v3")


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
    import requests

    client = Client(auth=("key", "secret"))
    endpoint = client.contact

    def mock_api_call(*args: object, **kwargs: object) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client, "api_call", mock_api_call)

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
