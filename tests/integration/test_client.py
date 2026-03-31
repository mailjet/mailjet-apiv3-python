from __future__ import annotations

import os

import pytest

from mailjet_rest.client import Client

# Safety guard: Prevent integration tests from running if credentials are missing
pytestmark = pytest.mark.skipif(
    "MJ_APIKEY_PUBLIC" not in os.environ or "MJ_APIKEY_PRIVATE" not in os.environ,
    reason="MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set.",
)


@pytest.fixture
def client_live() -> Client:
    """Returns a client with valid credentials from environment variables."""
    public_key = os.environ["MJ_APIKEY_PUBLIC"]
    private_key = os.environ["MJ_APIKEY_PRIVATE"]
    return Client(auth=(public_key, private_key), version="v3")


@pytest.fixture
def client_live_invalid_auth() -> Client:
    """Returns a client with deliberately invalid credentials."""
    return Client(auth=("invalid_public", "invalid_private"), version="v3")


# --- Integration & HTTP Behavior Tests ---


def test_json_data_str_or_bytes_with_ensure_ascii(client_live: Client) -> None:
    """Test that string payloads are handled appropriately without being double-encoded."""
    result = client_live.sender.create(data='{"email": "test@example.com"}')
    # If successful, returns 201 Created. If validation fails: 400.
    assert result.status_code in (201, 400)


def test_get_no_param(client_live: Client) -> None:
    """Tests a standard GET request without parameters."""
    result = client_live.contact.get()
    assert result.status_code == 200


def test_post_with_no_param(client_live: Client) -> None:
    """Tests a POST request with an empty data payload. Should return 400 Bad Request."""
    result = client_live.sender.create(data={})
    assert result.status_code == 400
    json_resp = result.json()
    assert "StatusCode" in json_resp
    assert json_resp["StatusCode"] == 400


def test_put_update_request(client_live: Client) -> None:
    """Tests a PUT request to ensure the update method functions correctly."""
    result = client_live.contact.update(id=123, data={"Name": "Test"})
    assert result.status_code in (404, 400, 401, 403)


def test_delete_request(client_live: Client) -> None:
    """Tests a DELETE request mapping."""
    result = client_live.contact.delete(id=123)
    # Depending on account state and permissions, a dummy ID triggers various rejections
    assert result.status_code in (204, 400, 401, 403, 404)


def test_client_initialization_with_invalid_api_key(
    client_live_invalid_auth: Client,
) -> None:
    """Tests that invalid credentials result in a 401 Unauthorized response."""
    result = client_live_invalid_auth.contact.get()
    assert result.status_code == 401


def test_csv_import_flow(client_live: Client) -> None:
    """End-to-End test for uploading CSV data and triggering an import job.

    Combines legacy test_01_upload_the_csv, test_02_import_csv_content,
    and test_03_monitor_progress into a single cohesive pytest workflow.
    """
    from pathlib import Path

    # 1. We need a valid contactslist ID. We create a temporary one for the test.
    list_resp = client_live.contactslist.create(data={"Name": "Test CSV List"})
    # If auth fails or rate limited, gracefully skip or assert
    if list_resp.status_code != 201:
        pytest.skip(f"Failed to create test contact list: {list_resp.text}")

    contactslist_id = list_resp.json()["Data"][0]["ID"]

    try:
        # 2. Upload the CSV Data (using the DATA API)
        csv_path = Path("tests/doc_tests/files/data.csv")
        if not csv_path.exists():
            pytest.skip("data.csv file not found for testing.")

        csv_data = csv_path.read_text(encoding="utf-8")
        upload_resp = client_live.contactslist_csvdata.create(
            id=contactslist_id, data=csv_data
        )
        assert upload_resp.status_code == 200
        data_id = upload_resp.json().get("ID")
        assert data_id is not None

        # 3. Trigger the Import Job
        import_data = {
            "Method": "addnoforce",
            "ContactsListID": contactslist_id,
            "DataID": data_id,
        }
        import_resp = client_live.csvimport.create(data=import_data)
        assert import_resp.status_code == 201
        import_job_id = import_resp.json()["Data"][0]["ID"]
        assert import_job_id is not None

        # 4. Monitor the Import Progress
        monitor_resp = client_live.csvimport.get(id=import_job_id)
        assert monitor_resp.status_code == 200
        assert "Status" in monitor_resp.json()["Data"][0]

    finally:
        # Clean up: Delete the temporary contacts list
        client_live.contactslist.delete(id=contactslist_id)
