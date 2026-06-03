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

    responses.add(responses.GET, "https://api.mailjet.com/v3/DATA/contactslist/123/CSVError/text:csv", json={})
    # This specifically triggers the 'CSVError' suffix logic
    client_offline.contactslist_csverror.get(id="123")
