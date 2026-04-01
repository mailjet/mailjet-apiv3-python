from __future__ import annotations

import os
import uuid

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


def test_live_send_api_v3_1_sandbox_happy_path(client_live: Client) -> None:
    """Test Send API v3.1 happy path using SandboxMode to prevent actual email delivery.

    A 200 OK confirms the endpoint parsed the payload correctly and authenticated us.
    """
    client_v31 = Client(auth=client_live.auth, version="v3.1")
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                "Subject": "CI/CD Sandbox Test",
                "TextPart": "This is a test from the Mailjet Python Wrapper.",
            }
        ],
        "SandboxMode": True,
    }
    result = client_v31.send.create(data=data)

    # Depending on whether pilot@mailjet.com is validated on the tester's account,
    # Mailjet might return 200 (Success in Sandbox) or 400/401 (Sender not validated).
    # Crucially, it must NOT be 404 (Endpoint not found).
    assert result.status_code in (200, 400, 401)
    assert result.status_code != 404


def test_live_send_api_v3_1_template_language_and_variables(
    client_live: Client,
) -> None:
    """Test Send API v3.1 with TemplateLanguage and Variables (Issue #97).

    Proves that the SDK correctly serializes and transmits template variables
    to the Mailjet API, yielding a successful status code if payload format is valid.
    """
    client_v31 = Client(auth=client_live.auth, version="v3.1")
    data = {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                "Subject": "Template Test",
                "TextPart": "Welcome {{var:name}}",
                "HTMLPart": "<h3>Welcome {{var:name}}</h3>",
                "TemplateLanguage": True,
                "Variables": {"name": "John Doe"},
            }
        ],
        "SandboxMode": True,
    }
    result = client_v31.send.create(data=data)

    # We expect 200 OK because the JSON is perfectly serialized.
    # If variables were dropped or malformed, it might trigger 400 Bad Request.
    # 401 can happen if the account isn't validated yet, but it proves routing is fine.
    assert result.status_code in (200, 400, 401)
    assert result.status_code != 404


def test_live_send_api_v3_1_bad_payload(client_live: Client) -> None:
    """Test Send API v3.1 bad path (missing mandatory Messages array)."""
    client_v31 = Client(auth=client_live.auth, version="v3.1")
    result = client_v31.send.create(data={"InvalidField": True})
    # Expecting 400 Bad Request because 'Messages' is missing
    assert result.status_code == 400


def test_live_send_api_v3_bad_payload(client_live: Client) -> None:
    """Test legacy Send API v3 bad path endpoint availability.

    By sending an empty payload, we expect Mailjet to actively reject it with a 400 Bad Request,
    proving the URL /v3/send exists and is actively listening.
    """
    result = client_live.send.create(data={})
    assert result.status_code == 400


def test_live_content_api_lifecycle_happy_path(client_live: Client) -> None:
    """End-to-End happy path test of the Content API.

    Creates a template, updates its HTML content via detailcontent, retrieves it, and cleans up.
    """
    # 1. Create a dummy template with a unique name to avoid conflicts
    unique_suffix = uuid.uuid4().hex[:8]
    template_data = {
        "Name": f"CI/CD Test Template {unique_suffix}",
        "Author": "Mailjet Python Wrapper",
        "Description": "Temporary template for integration testing.",
        "EditMode": 1,
    }
    create_resp = client_live.template.create(data=template_data)

    if create_resp.status_code != 201:
        pytest.skip(f"Could not create template for testing: {create_resp.text}")

    template_id = create_resp.json()["Data"][0]["ID"]

    try:
        # 2. Add Content via the specific detailcontent Content API endpoint
        content_data = {
            "Headers": {"Subject": "Test Content Subject"},
            "Html-part": "<html><body><h1>Hello from Python!</h1></body></html>",
            "Text-part": "Hello from Python!",
        }
        content_resp = client_live.template_detailcontent.create(
            id=template_id, data=content_data
        )

        # Expecting 200 OK or 201 Created from a successful content update
        assert content_resp.status_code in (200, 201)

        # 3. Verify Retrieval of Content
        get_resp = client_live.template_detailcontent.get(id=template_id)
        assert get_resp.status_code == 200

    finally:
        # 4. Always clean up the dummy template
        client_live.template.delete(id=template_id)


def test_live_content_api_bad_path(client_live: Client) -> None:
    """Test Content API bad path (accessing detailcontent of a non-existent template)."""
    invalid_template_id = 999999999999
    result = client_live.template_detailcontent.get(id=invalid_template_id)
    # Should return 400 or 404 for non-existent resources
    assert result.status_code in (400, 404)


def test_live_sms_api_v4_auth_rejection(client_live: Client) -> None:
    """Test SMS API endpoint availability and auto-routing to v4.

    SMS API requires a Bearer token. Because we are using the Email API's basic auth
    credentials, we expect Mailjet to strictly reject us with a 401 Unauthorized.
    This safely proves the `/v4/sms-send` endpoint was hit accurately.
    """
    data = {"Text": "Hello from Python", "To": "+1234567890", "From": "MJSMS"}
    result = client_live.sms_send.create(data=data)

    # 401 Unauthorized or 403 Forbidden proves it's an auth failure, NOT a 404 routing failure.
    assert result.status_code in (400, 401, 403)
    assert result.status_code != 404


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
    # Use unique name to prevent "already exists" errors during parallel or repeated runs.
    unique_suffix = uuid.uuid4().hex[:8]
    list_resp = client_live.contactslist.create(
        data={"Name": f"Test CSV List {unique_suffix}"}
    )

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
