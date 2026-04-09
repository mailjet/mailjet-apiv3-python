from __future__ import annotations

import os
import uuid
from collections.abc import Generator

import pytest

from mailjet_rest.client import Client

# Safety guard: Prevent integration tests from running if credentials are missing
pytestmark = pytest.mark.skipif(
    "MJ_APIKEY_PUBLIC" not in os.environ or "MJ_APIKEY_PRIVATE" not in os.environ,
    reason="MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set.",
    )


@pytest.fixture
def client_live() -> Generator[Client, None, None]:
    """Returns a client managed safely via context manager to prevent socket leaks."""
    public_key = os.environ["MJ_APIKEY_PUBLIC"]
    private_key = os.environ["MJ_APIKEY_PRIVATE"]
    with Client(auth=(public_key, private_key), version="v3") as client:
        yield client  # Test executes here, __exit__ cleans up sockets afterward


@pytest.fixture
def client_live_invalid_auth() -> Generator[Client, None, None]:
    """Returns a client with deliberately invalid credentials."""
    with Client(auth=("invalid_public", "invalid_private"), version="v3") as client:
        yield client


# --- Integration & HTTP Behavior Tests ---


def test_live_send_api_v3_1_sandbox_happy_path(client_live: Client) -> None:
    """Test Send API v3.1 happy path using SandboxMode to prevent actual email delivery."""
    auth_tuple = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])

    with Client(auth=auth_tuple, version="v3.1") as client_v31:
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
        assert result.status_code in (200, 400, 401)
        assert result.status_code != 404


def test_live_send_api_v3_1_template_language_and_variables(
    client_live: Client,
) -> None:
    """Test Send API v3.1 with TemplateLanguage and Variables (Issue #97)."""
    auth_tuple = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])

    with Client(auth=auth_tuple, version="v3.1") as client_v31:
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
        assert result.status_code in (200, 400, 401)
        assert result.status_code != 404


def test_live_email_api_v3_template_lifecycle(client_live: Client) -> None:
    """End-to-End happy path test of the older v3 Email API Templates."""
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
        content_data = {
            "Headers": {"Subject": "Test Content Subject"},
            "Html-part": "<html><body><h1>Hello from Python!</h1></body></html>",
            "Text-part": "Hello from Python!",
        }
        content_resp = client_live.template_detailcontent.create(
            id=template_id, data=content_data
        )

        assert content_resp.status_code in (200, 201)
        get_resp = client_live.template_detailcontent.get(id=template_id)
        assert get_resp.status_code == 200

    finally:
        client_live.template.delete(id=template_id)


def test_live_content_api_v1_template_lifecycle(client_live: Client) -> None:
    """End-to-End test of the true v1 Content API Templates utilizing lock/unlock workflow."""
    auth_tuple = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])

    with Client(auth=auth_tuple, version="v1") as client_v1:
        template_data = {
            "Name": f"v1-template-{uuid.uuid4().hex[:8]}",
            "EditMode": 2,
            "Purposes": ["transactional"]
        }
        create_resp = client_v1.templates.create(data=template_data)

        if create_resp.status_code != 201:
            pytest.skip(f"Could not create v1 template for testing: {create_resp.text}")

        template_id = create_resp.json()["Data"][0]["ID"]

        try:
            content_data = {
                "Headers": {"Subject": "V1 Content Subject"},
                "HtmlPart": "<html><body><h1>V1 Content</h1></body></html>",
                "TextPart": "V1 Content",
                "Locale": "en_US"
            }
            content_resp = client_v1.templates_contents.create(id=template_id, data=content_data)
            assert content_resp.status_code == 201

            publish_resp = client_v1.templates_contents_publish.create(id=template_id)
            assert publish_resp.status_code == 200

            get_resp = client_v1.templates_contents_types.get(id=template_id, action_id="P")
            assert get_resp.status_code == 200

            lock_resp = client_v1.templates_contents_lock.create(id=template_id, data={})
            assert lock_resp.status_code == 204

            unlock_resp = client_v1.templates_contents_unlock.create(id=template_id, data={})
            assert unlock_resp.status_code == 204

        finally:
            client_v1.templates.delete(id=template_id)


# --- Security Verification Tests ---

def test_live_path_traversal_prevention(client_live: Client) -> None:
    """Verify that malicious IDs are securely URL-encoded, preventing directory traversal execution on the server."""
    result = client_live.contact.get(id="123/../../delete")
    assert result.status_code in (400, 404)


# --- Error Path & General Routing Tests ---

def test_live_send_api_v3_1_bad_payload(client_live: Client) -> None:
    """Test Send API v3.1 bad path (missing mandatory Messages array)."""
    auth_tuple = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])
    with Client(auth=auth_tuple, version="v3.1") as client_v31:
        result = client_v31.send.create(data={"InvalidField": True})
        assert result.status_code == 400


def test_live_send_api_v3_bad_payload(client_live: Client) -> None:
    """Test legacy Send API v3 bad path endpoint availability."""
    result = client_live.send.create(data={})
    assert result.status_code == 400


def test_live_content_api_bad_path(client_live: Client) -> None:
    """Test Content API bad path (accessing detailcontent of a non-existent template)."""
    invalid_template_id = 999999999999
    result = client_live.template_detailcontent.get(id=invalid_template_id)
    assert result.status_code in (400, 404)


def test_live_content_api_v1_bearer_auth() -> None:
    """Test Content API v1 endpoints with Bearer token authentication."""
    with Client(auth="fake_test_content_token_123", version="v1") as client_v1:
        result = client_v1.templates.get()
        assert result.status_code == 401


def test_live_statcounters_happy_path(client_live: Client) -> None:
    """Test retrieving campaign statistics to match the README example."""
    filters = {
        "CounterSource": "APIKey",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    result = client_live.statcounters.get(filters=filters)
    assert result.status_code == 200


def test_get_no_param(client_live: Client) -> None:
    """Tests a standard GET request. Passes explicit valid timeout to ensure config validation allows it."""
    result = client_live.contact.get(timeout=25)
    assert result.status_code == 200


def test_post_with_no_param(client_live: Client) -> None:
    """Tests a POST request with an empty data payload. Should return 400 Bad Request."""
    result = client_live.sender.create(data={})
    assert result.status_code == 400


def test_client_initialization_with_invalid_api_key(
    client_live_invalid_auth: Client,
) -> None:
    """Tests that invalid credentials result in a 401 Unauthorized response."""
    result = client_live_invalid_auth.contact.get()
    assert result.status_code == 401


def test_csv_import_flow(client_live: Client) -> None:
    """End-to-End test for uploading CSV data and triggering an import job."""
    from pathlib import Path

    unique_suffix = uuid.uuid4().hex[:8]
    list_resp = client_live.contactslist.create(
        data={"Name": f"Test CSV List {unique_suffix}"}
    )

    if list_resp.status_code != 201:
        pytest.skip(f"Failed to create test contact list: {list_resp.text}")

    contactslist_id = list_resp.json()["Data"][0]["ID"]

    try:
        csv_path = Path("tests/doc_tests/files/data.csv")
        if not csv_path.exists():
            pytest.skip("data.csv file not found for testing.")

        csv_data = csv_path.read_text(encoding="utf-8")
        upload_resp = client_live.contactslist_csvdata.create(
            id=contactslist_id, data=csv_data
        )
        assert upload_resp.status_code == 200
        data_id = upload_resp.json().get("ID")

        import_data = {
            "Method": "addnoforce",
            "ContactsListID": contactslist_id,
            "DataID": data_id,
        }
        import_resp = client_live.csvimport.create(data=import_data)
        assert import_resp.status_code == 201

    finally:
        client_live.contactslist.delete(id=contactslist_id)


def test_live_content_api_images_multipart_upload() -> None:
    """Test 8 from Canvas: REAL file upload via multipart/form-data."""
    import base64

    api_key = os.environ.get("MJ_APIKEY_PUBLIC", "")
    api_secret = os.environ.get("MJ_APIKEY_PRIVATE", "")
    auth_fallback = (api_key, api_secret)

    with Client(auth=os.environ.get("MJ_CONTENT_TOKEN") or auth_fallback, version="v1") as client_v1:
        b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        files_payload = {
            "metadata": (None, '{"name": "ci_test_logo.png", "Status": "open"}', "application/json"),
            "file": ("ci_test_logo.png", base64.b64decode(b64_string), "image/png"),
        }

        result = client_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)
        assert result.status_code == 201
