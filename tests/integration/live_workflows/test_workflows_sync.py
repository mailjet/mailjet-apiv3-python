"""Synchronous live integration workflow tests for Mailjet Client."""

from __future__ import annotations

import base64
import contextlib
import json
import os
import uuid
from collections.abc import Generator
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from mailjet_rest import MailjetAuthError
from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
from mailjet_rest.client import Client
from mailjet_rest.errors import DoesNotExistError, ValidationError
from tests.integration.conftest import REPO_ROOT, get_live_auth, has_live_credentials


# Safety guard: Prevent integration tests from running if credentials are missing
pytestmark = pytest.mark.skipif(
    not has_live_credentials(),
    reason="MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set.",
)


@pytest.fixture
def client_live() -> Generator[Client, None, None]:
    """Return a live v3 Client managed via context manager to prevent socket leaks."""
    with Client(auth=get_live_auth(), version="v3") as client:
        yield client


@pytest.fixture
def client_live_invalid_auth() -> Generator[Client, None, None]:
    """Return a v3 Client configured with deliberately invalid credentials."""
    with Client(auth=("invalid_public", "invalid_private"), version="v3") as client:
        yield client


# --- Integration & HTTP Behavior Tests ---


def test_live_send_api_v3_1_sandbox_happy_path() -> None:
    """Test Send API v3.1 happy path using SandboxMode to prevent actual email delivery."""
    with Client(auth=get_live_auth(), version="v3.1") as client_v31:
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


def test_live_send_api_v3_1_template_language_and_variables() -> None:
    """Test Send API v3.1 with TemplateLanguage and Variables (Issue #97)."""
    with Client(auth=get_live_auth(), version="v3.1") as client_v31:
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
        content_resp = client_live.template_detailcontent.create(id=template_id, data=content_data)

        assert content_resp.status_code in (200, 201)
        get_resp = client_live.template_detailcontent.get(id=template_id)
        assert get_resp.status_code == 200

    finally:
        client_live.template.delete(id=template_id)


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_live_content_api_v1_template_lifecycle() -> None:
    """End-to-End test of the true v1 Content API Templates utilizing lock/unlock workflow."""
    with Client(auth=get_live_auth(), version="v1") as client_v1:
        template_data = {
            "Name": f"v1-template-{uuid.uuid4().hex[:8]}",
            "EditMode": 2,
            "Purposes": ["transactional"],
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
                "Locale": "en_US",
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


# --- Error Path & General Routing Tests ---


def test_live_send_api_v3_1_bad_payload() -> None:
    """Test Send API v3.1 bad path (missing mandatory Messages array)."""
    with Client(auth=get_live_auth(), version="v3.1") as client_v31:
        with pytest.raises(ValidationError) as excinfo:
            client_v31.send.create(data={"InvalidField": True})
        assert excinfo.value.status_code == 400


def test_live_send_api_v3_bad_payload(client_live: Client) -> None:
    """Test legacy Send API v3 bad path endpoint availability."""
    with pytest.raises(ValidationError) as excinfo:
        client_live.send.create(data={})
    assert excinfo.value.status_code == 400


def test_live_content_api_bad_path(client_live: Client) -> None:
    """Test Content API bad path (accessing detailcontent of a non-existent template)."""
    invalid_template_id = 999999999999
    with pytest.raises((DoesNotExistError, ValidationError)) as excinfo:
        client_live.template_detailcontent.get(id=invalid_template_id)
    assert excinfo.value.status_code in (400, 404)


def test_live_content_api_v1_bearer_auth() -> None:
    """Test Content API v1 endpoints with Bearer token authentication."""
    with Client(auth="fake_test_content_token_123", version="v1") as client_v1:
        with pytest.raises(MailjetAuthError) as excinfo:
            client_v1.templates.get()
        assert excinfo.value.status_code == 401


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
    with pytest.raises(ValidationError) as excinfo:
        client_live.sender.create(data={})
    assert excinfo.value.status_code == 400


def test_client_initialization_with_invalid_api_key(client_live_invalid_auth: Client) -> None:
    """Tests that invalid credentials result in a 401 Unauthorized response when performing an operation."""
    with pytest.raises(MailjetAuthError) as excinfo:
        client_live_invalid_auth.contact.get()

    assert excinfo.value.status_code == 401


def test_csv_import_flow(client_live: Client) -> None:
    """End-to-End test for uploading CSV data and triggering an import job."""
    unique_suffix = uuid.uuid4().hex[:8]
    list_resp = client_live.contactslist.create(data={"Name": f"Test CSV List {unique_suffix}"})

    if list_resp.status_code != 201:
        pytest.skip(f"Failed to create test contact list: {list_resp.text}")

    contactslist_id = list_resp.json()["Data"][0]["ID"]

    try:
        csv_path = REPO_ROOT / "tests" / "doc_tests" / "files" / "data.csv"
        if not csv_path.exists():
            pytest.skip("data.csv file not found for testing.")

        csv_data = csv_path.read_text(encoding="utf-8")
        upload_resp = client_live.contactslist_csvdata.create(id=contactslist_id, data=csv_data)
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
    """Real file upload via multipart/form-data on v1 data_images."""
    auth_value: tuple[str, str] | str = os.environ.get("MJ_CONTENT_TOKEN") or get_live_auth()

    with Client(auth=auth_value, version="v1") as client_v1:
        b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
        unique_name = f"ci_test_logo_{uuid.uuid4().hex[:8]}.png"
        metadata_json = json.dumps({"name": unique_name, "Status": "open"})

        files_payload = {
            "metadata": (None, metadata_json, "application/json"),
            "file": (unique_name, base64.b64decode(b64_string), "image/png"),
        }

        try:
            result = client_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)
            assert result.status_code in (200, 201)

            image_id = result.json()["Data"][0]["ID"]
            with contextlib.suppress(Exception):
                client_v1.data_images.delete(id=image_id)
        except ValidationError as e:
            pytest.skip(
                f"Skipping: Mailjet image quota likely exceeded or payload rejected (400). Details: {e.response_body}"
            )


def test_live_contact_crud_lifecycle(client_live: Client) -> None:
    """Integration test for Contact creation, retrieval, updating, and deletion."""
    test_email = f"ci-test-contact-{uuid.uuid4().hex[:8]}@example.com"

    create_resp = client_live.contact.create(data={"Email": test_email, "IsExcludedFromCampaigns": "true"})
    assert create_resp.status_code == 201
    contact_id = create_resp.json()["Data"][0]["ID"]

    try:
        get_resp = client_live.contact.get(id=contact_id)
        assert get_resp.status_code == 200
        assert get_resp.json()["Data"][0]["Email"] == test_email

        update_resp = client_live.contact.update(id=contact_id, data={"Name": "CI Test User"})
        assert update_resp.status_code == 200

    finally:
        try:
            delete_resp = client_live.contact.delete(id=contact_id)
            assert delete_resp.status_code in (200, 204)
        except MailjetAuthError as e:
            assert e.status_code == 401
        except Exception as e:
            pytest.fail(f"Live network call failed at the transport layer: {e}")


def test_live_template_crud_lifecycle(client_live: Client) -> None:
    """Integration test for Template shell creation, content modification, and deletion."""
    template_name = f"CI Test Template {uuid.uuid4().hex[:8]}"

    create_data = {
        "Name": template_name,
        "Author": "Mailjet Python CI",
        "EditMode": 1,
        "IsTextPartGenerationEnabled": True,
        "Locale": "en_US",
    }
    create_resp = client_live.template.create(data=create_data)
    assert create_resp.status_code == 201
    template_id = create_resp.json()["Data"][0]["ID"]

    try:
        content_data = {"Html-part": "<html><body><h1>Hello from CI</h1></body></html>", "Text-part": "Hello from CI"}
        content_resp = client_live.template_detailcontent.create(id=template_id, data=content_data)
        assert content_resp.status_code in (200, 201)

    finally:
        delete_resp = client_live.template.delete(id=template_id)
        assert delete_resp.status_code in (200, 204)


def test_live_readonly_endpoints(client_live: Client) -> None:
    """Verify that basic read operations work across multiple core endpoints."""
    endpoints_to_test = [client_live.sender, client_live.message, client_live.campaign, client_live.contactfilter]

    for endpoint in endpoints_to_test:
        resp = endpoint.get(filters={"limit": 1})
        assert resp.status_code == 200
        assert "Data" in resp.json(), f"Endpoint {endpoint.name} did not return 'Data' payload."


def test_live_auth_failure_handling(client_live_invalid_auth: Client) -> None:
    """Verify that invalid credentials raise MailjetAuthError."""
    with pytest.raises(MailjetAuthError) as excinfo:
        client_live_invalid_auth.contact.get(filters={"limit": 1})
    assert excinfo.value.status_code == 401


def test_live_message_builder_sandbox(tmp_path: Path) -> None:
    """Integration test for MessageBuilder in a live sandbox environment."""
    with Client(auth=get_live_auth(), version="v3.1") as client_v31:
        builder = MessageBuilder()
        builder.set_sender("test@example.com", "CI Integration")
        builder.set_reply_to("no-reply@example.com")
        builder.add_recipient("passenger@example.com", "Passenger 1")
        builder.add_cc("copilot@example.com")
        builder.add_bcc("tower@example.com")
        builder.set_subject("Your Integration Flight is Confirmed")
        builder.set_content(text="Flight details...", html="<h3>Flight details...</h3>")

        attachment_file = tmp_path / f"sandbox_attachment_{uuid.uuid4().hex[:8]}.txt"
        attachment_file.write_bytes(b"Hello from CI!")
        builder.attach_file(attachment_file, base_dir=tmp_path)

        message = builder.build()
        message["CustomID"] = f"IntegrationTest-Telemetry-{uuid.uuid4().hex[:8]}"

        payload = {
            "Messages": [message],
            "SandboxMode": True,
        }

        resp = client_v31.send.create(data=payload)
        assert resp.status_code == 200
        assert "Messages" in resp.json()


def test_live_template_content_builder_lifecycle(client_live: Client) -> None:
    """Integration test for TemplateContentBuilder covering creation, update, and deletion."""
    template_name = f"CI_Builder_Test_{uuid.uuid4().hex[:8]}"
    create_resp = client_live.template.create(
        data={"Name": template_name, "Author": "CI Process", "EditMode": 1, "Purposes": ["transactional"]}
    )
    assert create_resp.status_code == 201
    template_id = create_resp.json()["Data"][0]["ID"]

    try:
        builder = TemplateContentBuilder()
        builder.set_meta(author="CI Process", name="CI Test Name", locale="en_US")
        builder.set_headers({"Subject": "Automated Integration Lifecycle"})
        builder.set_content(
            text="This is text built by CI.",
            html="<html><body><h1>Built by CI</h1></body></html>",
            mjml="<mjml><mj-body></mj-body></mjml>",
        )
        content_payload = builder.build()

        content_resp = client_live.template_detailcontent.create(id=template_id, data=content_payload)
        assert content_resp.status_code in (200, 201)
    finally:
        client_live.template.delete(id=template_id)


def test_live_endpoint_stream_pagination(client_live: Client) -> None:
    """Verify the lazy evaluation .stream() method handles pagination accurately."""
    streamer = client_live.contact.stream(filters={"Limit": 3}, chunk_size=2)
    contacts = []

    for contact in streamer:
        contacts.append(contact)
        if len(contacts) >= 3:
            break

    assert isinstance(contacts, list)
    if contacts:
        assert "ID" in contacts[0]


def test_live_client_custom_timeout_and_config() -> None:
    """Verify explicit tuple timeouts and config overrides trigger correctly."""
    with Client(auth=get_live_auth(), version="v3", timeout=(3.05, 12.5)) as client:
        resp = client.myprofile.get()
        assert resp.status_code == 200


def test_live_message_builder_exhaustive_options(tmp_path: Path) -> None:
    """Integration test hitting all optional paths of MessageBuilder and guardrails."""
    with Client(auth=get_live_auth(), version="v3.1") as client_v31:
        builder = MessageBuilder()
        builder.set_sender("sender@example.com", "Exhaustive CI Sender")
        builder.set_reply_to("reply@example.com")
        builder.add_recipient("recipient@example.com", "Primary Recipient")
        builder.add_cc("cc@example.com", "CC Recipient")
        builder.add_bcc("bcc@example.com", "BCC Recipient")
        builder.set_subject("Exhaustive Sandbox Test")
        builder.set_content(text="Plain text body", html="<p>HTML body with <script>alert(1)</script></p>")
        builder.set_headers({"X-Custom-Header": "CustomValue"})

        temp_file = tmp_path / f"ci_temp_attachment_{uuid.uuid4().hex[:8]}.txt"
        temp_file.write_text("Attachment content for integration test.", encoding="utf-8")
        builder.attach_file(temp_file, base_dir=tmp_path)

        message = builder.build()
        message["CustomID"] = f"Exhaustive-Telemetry-{uuid.uuid4().hex[:8]}"

        payload = {"Messages": [message], "SandboxMode": True}

        resp = client_v31.send.create(data=payload)
        assert resp.status_code == 200
        assert "Messages" in resp.json()


def test_live_template_content_builder_exhaustive(client_live: Client) -> None:
    """Integration test hitting all options of TemplateContentBuilder."""
    template_name = f"Exhaustive_Tpl_{uuid.uuid4().hex[:8]}"
    create_resp = client_live.template.create(
        data={"Name": template_name, "Author": "Exhaustive CI", "EditMode": 1, "Purposes": ["transactional"]}
    )
    assert create_resp.status_code == 201
    template_id = create_resp.json()["Data"][0]["ID"]

    try:
        builder = TemplateContentBuilder()
        builder.set_meta(author="CI Runner", name="Override Name", locale="fr_FR")
        builder.set_headers({"Subject": "Template Content Subject"})
        builder.set_content(
            text="Template plain text.",
            html="<div>Template HTML content</div>",
            mjml="<mjml><mj-body><mj-text>Hello</mj-text></mj-body></mjml>",
        )
        content_payload = builder.build()

        content_resp = client_live.template_detailcontent.create(id=template_id, data=content_payload)
        assert content_resp.status_code in (200, 201)
    finally:
        client_live.template.delete(id=template_id)


def test_live_custom_headers_propagation(client_live: Client) -> None:
    """Verify that custom headers pass cleanly through endpoint operations."""
    custom_headers = {"X-Request-Source": "CI-Runner", "X-Integration-Test": "True"}
    resp = client_live.contact.get(filters={"limit": 1}, headers=custom_headers)
    assert resp.status_code == 200


def test_live_stream_with_parse_qs_filters(client_live: Client) -> None:
    """Verify endpoint.stream correctly casts multidicts from parse_qs during live pagination."""
    query_filters = parse_qs("offset=0&limit=2")
    streamer = client_live.contact.stream(filters=query_filters, chunk_size=2)

    items = []
    for item in streamer:
        items.append(item)
        if len(items) >= 2:
            break

    assert isinstance(items, list)
    if items:
        assert "ID" in items[0]


def test_live_account_metadata_endpoints(client_live: Client) -> None:
    """Verify live read-only access to account and configuration endpoints."""
    resp_meta = client_live.contactmetadata.get(filters={"limit": 1})
    assert resp_meta.status_code == 200
    assert "Data" in resp_meta.json()

    resp_dns = client_live.dns.get(filters={"limit": 1})
    assert resp_dns.status_code == 200
    assert "Data" in resp_dns.json()

    resp_key = client_live.apikey.get(filters={"limit": 1})
    assert resp_key.status_code == 200


def test_live_event_statistics_endpoints(client_live: Client) -> None:
    """Verify real-time event tracking and statistics log retrieval."""
    for stats_endpoint in (
        "bouncestatistics",
        "clickstatistics",
        "openinformation",
        "toplinkclicked",
        "useragentstatistics",
    ):
        endpoint = getattr(client_live, stats_endpoint)
        resp = endpoint.get(filters={"limit": 1})
        assert resp.status_code == 200
        assert "Data" in resp.json()


def test_live_eventcallbackurl_crud_lifecycle(client_live: Client) -> None:
    """End-to-End test for webhook (eventcallbackurl) management."""
    existing = client_live.eventcallbackurl.get(filters={"EventType": "open", "IsBackup": False})
    if existing.status_code == 200 and existing.json().get("Data"):
        for item in existing.json()["Data"]:
            client_live.eventcallbackurl.delete(id=item["ID"])

    webhook_url = f"https://example.com/webhook_{uuid.uuid4().hex[:8]}"

    create_resp = client_live.eventcallbackurl.create(
        data={
            "EventType": "open",
            "Url": webhook_url,
            "Status": "alive",
            "IsBackup": False,
        }
    )
    if create_resp.status_code != 201:
        pytest.skip(f"Webhook setup not permitted: {create_resp.text}")

    webhook_id = create_resp.json()["Data"][0]["ID"]

    try:
        get_resp = client_live.eventcallbackurl.get(id=webhook_id)
        assert get_resp.status_code == 200
        assert get_resp.json()["Data"][0]["Url"] == webhook_url

        update_resp = client_live.eventcallbackurl.update(
            id=webhook_id,
            data={"Status": "dead"},
        )
        assert update_resp.status_code == 200
    finally:
        client_live.eventcallbackurl.delete(id=webhook_id)


def test_live_statistics_link_click_and_recipient_esp(client_live: Client) -> None:
    """Verify live read queries on statistics/link-click and statistics/recipient-esp."""
    try:
        resp_click = client_live.statistics_linkClick.get(filters={"CampaignID": 1})
        assert resp_click.status_code in (200, 404)
        if resp_click.status_code == 200:
            assert "Data" in resp_click.json()
    except (DoesNotExistError, ValidationError) as e:
        assert getattr(e, "status_code", 404) in (400, 404)

    try:
        resp_esp = client_live.statistics_recipientEsp.get(filters={"CampaignID": 1})
        assert resp_esp.status_code in (200, 404)
        if resp_esp.status_code == 200:
            assert "Data" in resp_esp.json()
    except (DoesNotExistError, ValidationError) as e:
        assert getattr(e, "status_code", 404) in (400, 404)


def test_live_contact_subresources_and_actions(client_live: Client) -> None:
    """Verify live URI interpolation on multi-segment contact sub-resources."""
    test_email = f"ci-subresource-{uuid.uuid4().hex[:8]}@example.com"
    create_contact = client_live.contact.create(data={"Email": test_email})
    if create_contact.status_code != 201:
        pytest.skip(f"Contact creation failed: {create_contact.text}")

    contact_id = create_contact.json()["Data"][0]["ID"]

    list_name = f"CI_List_{uuid.uuid4().hex[:8]}"
    create_list = client_live.contactslist.create(data={"Name": list_name})
    if create_list.status_code != 201:
        with contextlib.suppress(MailjetAuthError):
            client_live.contact.delete(id=contact_id)
        pytest.skip(f"ContactsList creation failed: {create_list.text}")

    list_id = create_list.json()["Data"][0]["ID"]

    try:
        sub_payload = {"ContactsLists": [{"ListID": list_id, "Action": "addnoforce"}]}
        resp_manage = client_live.contact_managecontactslists.create(
            id=contact_id,
            data=sub_payload,
        )
        assert resp_manage.status_code in (200, 201)

        resp_getlists = client_live.contact_getcontactslists.get(id=contact_id)
        assert resp_getlists.status_code == 200
        assert "Data" in resp_getlists.json()

        many_payload = {
            "Action": "addnoforce",
            "Contacts": [{"Email": test_email}],
        }
        resp_many = client_live.contactslist_managemanycontacts.create(
            id=list_id,
            data=many_payload,
        )
        assert resp_many.status_code in (200, 201)

    finally:
        with contextlib.suppress(MailjetAuthError):
            client_live.contact.delete(id=contact_id)

        with contextlib.suppress(MailjetAuthError, DoesNotExistError):
            client_live.contactslist.delete(id=list_id)
