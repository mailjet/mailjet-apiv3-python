import pytest
import responses

from mailjet_rest.client import Client


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
