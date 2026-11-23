"""Asynchronous live integration workflow tests for Mailjet AsyncClient."""

from __future__ import annotations

import asyncio
import base64
import contextlib
import json
import os
import uuid
from pathlib import Path
from urllib.parse import parse_qs

import pytest

from mailjet_rest import MailjetAuthError
from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import DoesNotExistError, ValidationError
from tests.integration.conftest import REPO_ROOT, get_live_auth, has_live_credentials


# Safety guard: Prevent live integration tests from running if credentials or httpx2 are missing
pytestmark = [
    pytest.mark.skipif(
        not has_live_credentials(),
        reason="MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set.",
    ),
    pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed."),
]


# --- Integration & HTTP Behavior Tests ---


def test_live_send_api_v3_1_sandbox_happy_path() -> None:
    """Test AsyncClient Send API v3.1 happy path using SandboxMode to prevent actual email delivery."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3.1") as client_v31:
            data = {
                "Messages": [
                    {
                        "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                        "To": [{"Email": "passenger1@mailjet.com", "Name": "passenger 1"}],
                        "Subject": "Async CI/CD Sandbox Test",
                        "TextPart": "This is a test from the Mailjet Python Async Wrapper.",
                    }
                ],
                "SandboxMode": True,
            }
            result = await client_v31.send.create(data=data)
            assert result.status_code in (200, 400, 401)
            assert result.status_code != 404

    asyncio.run(_run())


def test_live_send_api_v3_1_template_language_and_variables() -> None:
    """Test AsyncClient Send API v3.1 with TemplateLanguage and Variables (Issue #97)."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3.1") as client_v31:
            data = {
                "Messages": [
                    {
                        "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                        "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                        "Subject": "Async Template Test",
                        "TextPart": "Welcome {{var:name}}",
                        "HTMLPart": "<h3>Welcome {{var:name}}</h3>",
                        "TemplateLanguage": True,
                        "Variables": {"name": "John Doe"},
                    }
                ],
                "SandboxMode": True,
            }
            result = await client_v31.send.create(data=data)
            assert result.status_code in (200, 400, 401)
            assert result.status_code != 404

    asyncio.run(_run())


def test_live_email_api_v3_template_lifecycle() -> None:
    """End-to-End happy path test of the older v3 Email API Templates via AsyncClient."""

    async def _run() -> None:
        unique_suffix = uuid.uuid4().hex[:8]
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            template_data = {
                "Name": f"CI/CD Async Test Template {unique_suffix}",
                "Author": "Mailjet Python Async Wrapper",
                "Description": "Temporary template for async integration testing.",
                "EditMode": 1,
            }
            create_resp = await client_live.template.create(data=template_data)

            if create_resp.status_code != 201:
                pytest.skip(f"Could not create template for testing: {create_resp.text}")

            template_id = create_resp.json()["Data"][0]["ID"]

            try:
                content_data = {
                    "Headers": {"Subject": "Async Test Content Subject"},
                    "Html-part": "<html><body><h1>Hello from Async Python!</h1></body></html>",
                    "Text-part": "Hello from Async Python!",
                }
                content_resp = await client_live.template_detailcontent.create(id=template_id, data=content_data)

                assert content_resp.status_code in (200, 201)
                get_resp = await client_live.template_detailcontent.get(id=template_id)
                assert get_resp.status_code == 200

            finally:
                await client_live.template.delete(id=template_id)

    asyncio.run(_run())


@pytest.mark.filterwarnings("ignore::DeprecationWarning")
def test_live_content_api_v1_template_lifecycle() -> None:
    """End-to-End test of the true v1 Content API Templates utilizing lock/unlock workflow via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v1") as client_v1:
            template_data = {
                "Name": f"async-v1-template-{uuid.uuid4().hex[:8]}",
                "EditMode": 2,
                "Purposes": ["transactional"],
            }
            create_resp = await client_v1.templates.create(data=template_data)

            if create_resp.status_code != 201:
                pytest.skip(f"Could not create v1 template for testing: {create_resp.text}")

            template_id = create_resp.json()["Data"][0]["ID"]

            try:
                content_data = {
                    "Headers": {"Subject": "Async V1 Content Subject"},
                    "HtmlPart": "<html><body><h1>Async V1 Content</h1></body></html>",
                    "TextPart": "Async V1 Content",
                    "Locale": "en_US",
                }
                content_resp = await client_v1.templates_contents.create(id=template_id, data=content_data)
                assert content_resp.status_code == 201

                publish_resp = await client_v1.templates_contents_publish.create(id=template_id)
                assert publish_resp.status_code == 200

                get_resp = await client_v1.templates_contents_types.get(id=template_id, action_id="P")
                assert get_resp.status_code == 200

                lock_resp = await client_v1.templates_contents_lock.create(id=template_id, data={})
                assert lock_resp.status_code == 204

                unlock_resp = await client_v1.templates_contents_unlock.create(id=template_id, data={})
                assert unlock_resp.status_code == 204

            finally:
                await client_v1.templates.delete(id=template_id)

    asyncio.run(_run())


# --- Error Path & General Routing Tests ---


def test_live_send_api_v3_1_bad_payload() -> None:
    """Test AsyncClient Send API v3.1 bad path (missing mandatory Messages array)."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3.1") as client_v31:
            with pytest.raises(ValidationError) as excinfo:
                await client_v31.send.create(data={"InvalidField": True})
            assert excinfo.value.status_code == 400

    asyncio.run(_run())


def test_live_send_api_v3_bad_payload() -> None:
    """Test legacy Send API v3 bad path endpoint availability via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            with pytest.raises(ValidationError) as excinfo:
                await client_live.send.create(data={})
            assert excinfo.value.status_code == 400

    asyncio.run(_run())


def test_live_content_api_bad_path() -> None:
    """Test Content API bad path (accessing detailcontent of a non-existent template) via AsyncClient."""

    async def _run() -> None:
        invalid_template_id = 999999999999
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            with pytest.raises((DoesNotExistError, ValidationError)) as excinfo:
                await client_live.template_detailcontent.get(id=invalid_template_id)
            assert excinfo.value.status_code in (400, 404)

    asyncio.run(_run())


def test_live_content_api_v1_bearer_auth() -> None:
    """Test Content API v1 endpoints with Bearer token authentication via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth="fake_test_content_token_123", version="v1") as client_v1:
            with pytest.raises(MailjetAuthError) as excinfo:
                await client_v1.templates.get()
            assert excinfo.value.status_code == 401

    asyncio.run(_run())


def test_live_statcounters_happy_path() -> None:
    """Test retrieving campaign statistics via AsyncClient."""

    async def _run() -> None:
        filters = {
            "CounterSource": "APIKey",
            "CounterTiming": "Message",
            "CounterResolution": "Lifetime",
        }
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            result = await client_live.statcounters.get(filters=filters)
            assert result.status_code == 200

    asyncio.run(_run())


def test_get_no_param() -> None:
    """Test a standard GET request with explicit valid timeout via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            result = await client_live.contact.get(timeout=25)
            assert result.status_code == 200

    asyncio.run(_run())


def test_post_with_no_param() -> None:
    """Test a POST request with an empty data payload via AsyncClient. Should return 400 Bad Request."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            with pytest.raises(ValidationError) as excinfo:
                await client_live.sender.create(data={})
            assert excinfo.value.status_code == 400

    asyncio.run(_run())


def test_client_initialization_with_invalid_api_key() -> None:
    """Test that invalid credentials result in a 401 Unauthorized response via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=("invalid_public", "invalid_private"), version="v3") as client_invalid:
            with pytest.raises(MailjetAuthError) as excinfo:
                await client_invalid.contact.get()
            assert excinfo.value.status_code == 401

    asyncio.run(_run())


def test_csv_import_flow() -> None:
    """End-to-End test for uploading CSV data and triggering an import job via AsyncClient."""

    async def _run() -> None:
        unique_suffix = uuid.uuid4().hex[:8]
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            list_resp = await client_live.contactslist.create(data={"Name": f"Test Async CSV List {unique_suffix}"})

            if list_resp.status_code != 201:
                pytest.skip(f"Failed to create test contact list: {list_resp.text}")

            contactslist_id = list_resp.json()["Data"][0]["ID"]

            try:
                csv_path = REPO_ROOT / "tests" / "doc_tests" / "files" / "data.csv"
                if not csv_path.exists():
                    pytest.skip("data.csv file not found for testing.")

                csv_data = csv_path.read_text(encoding="utf-8")
                upload_resp = await client_live.contactslist_csvdata.create(id=contactslist_id, data=csv_data)
                assert upload_resp.status_code == 200
                data_id = upload_resp.json().get("ID")

                import_data = {
                    "Method": "addnoforce",
                    "ContactsListID": contactslist_id,
                    "DataID": data_id,
                }
                import_resp = await client_live.csvimport.create(data=import_data)
                assert import_resp.status_code == 201

            finally:
                await client_live.contactslist.delete(id=contactslist_id)

    asyncio.run(_run())


def test_live_content_api_images_multipart_upload() -> None:
    """Real file upload via multipart/form-data on v1 data_images via AsyncClient."""

    async def _run() -> None:
        auth_value: tuple[str, str] | str = os.environ.get("MJ_CONTENT_TOKEN") or get_live_auth()

        async with AsyncClient(auth=auth_value, version="v1") as client_v1:
            b64_string = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="
            unique_name = f"async_ci_test_logo_{uuid.uuid4().hex[:8]}.png"
            metadata_json = json.dumps({"name": unique_name, "Status": "open"})

            files_payload = {
                "metadata": (None, metadata_json, "application/json"),
                "file": (unique_name, base64.b64decode(b64_string), "image/png"),
            }

            try:
                result = await client_v1.data_images.create(headers={"Content-Type": None}, files=files_payload)
                assert result.status_code in (200, 201)

                image_id = result.json()["Data"][0]["ID"]
                with contextlib.suppress(Exception):
                    await client_v1.data_images.delete(id=image_id)
            except ValidationError as e:
                pytest.skip(
                    f"Skipping: Mailjet image quota likely exceeded or payload rejected (400). "
                    f"Details: {e.response_body}"
                )

    asyncio.run(_run())


def test_live_contact_crud_lifecycle() -> None:
    """Integration test for Contact creation, retrieval, updating, and deletion via AsyncClient."""

    async def _run() -> None:
        test_email = f"async-ci-test-contact-{uuid.uuid4().hex[:8]}@example.com"

        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            assert isinstance(client_live.contact, AsyncEndpoint)
            create_resp = await client_live.contact.create(
                data={"Email": test_email, "IsExcludedFromCampaigns": "true"}
            )
            assert create_resp.status_code == 201
            contact_id = create_resp.json()["Data"][0]["ID"]

            try:
                get_resp = await client_live.contact.get(id=contact_id)
                assert get_resp.status_code == 200
                assert get_resp.json()["Data"][0]["Email"] == test_email

                update_resp = await client_live.contact.update(id=contact_id, data={"Name": "Async CI Test User"})
                assert update_resp.status_code == 200

            finally:
                try:
                    delete_resp = await client_live.contact.delete(id=contact_id)
                    assert delete_resp.status_code in (200, 204)
                except MailjetAuthError as e:
                    assert e.status_code == 401
                except Exception as e:
                    pytest.fail(f"Live async network call failed at the transport layer: {e}")

    asyncio.run(_run())


def test_live_template_crud_lifecycle() -> None:
    """Integration test for Template shell creation, content modification, and deletion via AsyncClient."""

    async def _run() -> None:
        template_name = f"Async CI Test Template {uuid.uuid4().hex[:8]}"

        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            create_data = {
                "Name": template_name,
                "Author": "Mailjet Python Async CI",
                "EditMode": 1,
                "IsTextPartGenerationEnabled": True,
                "Locale": "en_US",
            }
            create_resp = await client_live.template.create(data=create_data)
            assert create_resp.status_code == 201
            template_id = create_resp.json()["Data"][0]["ID"]

            try:
                content_data = {
                    "Html-part": "<html><body><h1>Hello from Async CI</h1></body></html>",
                    "Text-part": "Hello from Async CI",
                }
                content_resp = await client_live.template_detailcontent.create(id=template_id, data=content_data)
                assert content_resp.status_code in (200, 201)

            finally:
                delete_resp = await client_live.template.delete(id=template_id)
                assert delete_resp.status_code in (200, 204)

    asyncio.run(_run())


def test_live_readonly_endpoints() -> None:
    """Verify that basic read operations work across multiple core endpoints via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            endpoints_to_test = [
                client_live.sender,
                client_live.message,
                client_live.campaign,
                client_live.contactfilter,
            ]

            for endpoint in endpoints_to_test:
                resp = await endpoint.get(filters={"limit": 1})
                assert resp.status_code == 200
                assert "Data" in resp.json(), f"Endpoint {endpoint.name} did not return 'Data' payload."

    asyncio.run(_run())


def test_live_auth_failure_handling() -> None:
    """Verify that invalid credentials raise MailjetAuthError via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=("invalid_public", "invalid_private"), version="v3") as client_invalid:
            with pytest.raises(MailjetAuthError) as excinfo:
                await client_invalid.contact.get(filters={"limit": 1})
            assert excinfo.value.status_code == 401

    asyncio.run(_run())


def test_live_message_builder_sandbox(tmp_path: Path) -> None:
    """Integration test for MessageBuilder in a live sandbox environment via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3.1") as client_v31:
            builder = MessageBuilder()
            builder.set_sender("test@example.com", "Async CI Integration")
            builder.set_reply_to("no-reply@example.com")
            builder.add_recipient("passenger@example.com", "Passenger 1")
            builder.add_cc("copilot@example.com")
            builder.add_bcc("tower@example.com")
            builder.set_subject("Your Async Integration Flight is Confirmed")
            builder.set_content(text="Flight details...", html="<h3>Flight details...</h3>")

            attachment_file = tmp_path / f"async_sandbox_attachment_{uuid.uuid4().hex[:8]}.txt"
            attachment_file.write_bytes(b"Hello from Async CI!")
            builder.attach_file(attachment_file, base_dir=tmp_path)

            message = builder.build()
            message["CustomID"] = f"Async-IntegrationTest-Telemetry-{uuid.uuid4().hex[:8]}"

            payload = {
                "Messages": [message],
                "SandboxMode": True,
            }

            resp = await client_v31.send.create(data=payload)
            assert resp.status_code == 200
            assert "Messages" in resp.json()

    asyncio.run(_run())


def test_live_template_content_builder_lifecycle() -> None:
    """Integration test for TemplateContentBuilder covering creation, update, and deletion via AsyncClient."""

    async def _run() -> None:
        template_name = f"Async_CI_Builder_Test_{uuid.uuid4().hex[:8]}"
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            create_resp = await client_live.template.create(
                data={"Name": template_name, "Author": "Async CI Process", "EditMode": 1, "Purposes": ["transactional"]}
            )
            assert create_resp.status_code == 201
            template_id = create_resp.json()["Data"][0]["ID"]

            try:
                builder = TemplateContentBuilder()
                builder.set_meta(author="Async CI Process", name="Async CI Test Name", locale="en_US")
                builder.set_headers({"Subject": "Automated Async Integration Lifecycle"})
                builder.set_content(
                    text="This is text built by Async CI.",
                    html="<html><body><h1>Built by Async CI</h1></body></html>",
                    mjml="<mjml><mj-body></mj-body></mjml>",
                )
                content_payload = builder.build()

                content_resp = await client_live.template_detailcontent.create(id=template_id, data=content_payload)
                assert content_resp.status_code in (200, 201)
            finally:
                await client_live.template.delete(id=template_id)

    asyncio.run(_run())


def test_live_endpoint_stream_pagination() -> None:
    """Verify the async lazy evaluation .stream() method handles pagination accurately."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            contacts = []
            async for contact in client_live.contact.stream(filters={"Limit": 3}, chunk_size=2):
                contacts.append(contact)
                if len(contacts) >= 3:
                    break

            assert isinstance(contacts, list)
            if contacts:
                assert "ID" in contacts[0]

    asyncio.run(_run())


def test_live_client_custom_timeout_and_config() -> None:
    """Verify explicit tuple timeouts and config overrides trigger correctly on AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3", timeout=(3.05, 12.5)) as client:
            resp = await client.myprofile.get()
            assert resp.status_code == 200

    asyncio.run(_run())


def test_live_message_builder_exhaustive_options(tmp_path: Path) -> None:
    """Integration test hitting all optional paths of MessageBuilder and guardrails via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3.1") as client_v31:
            builder = MessageBuilder()
            builder.set_sender("sender@example.com", "Exhaustive Async CI Sender")
            builder.set_reply_to("reply@example.com")
            builder.add_recipient("recipient@example.com", "Primary Recipient")
            builder.add_cc("cc@example.com", "CC Recipient")
            builder.add_bcc("bcc@example.com", "BCC Recipient")
            builder.set_subject("Exhaustive Async Sandbox Test")
            builder.set_content(text="Plain text body", html="<p>HTML body with <script>alert(1)</script></p>")
            builder.set_headers({"X-Custom-Header": "CustomValue"})

            temp_file = tmp_path / f"async_ci_temp_attachment_{uuid.uuid4().hex[:8]}.txt"
            temp_file.write_text("Attachment content for async integration test.", encoding="utf-8")
            builder.attach_file(temp_file, base_dir=tmp_path)

            message = builder.build()
            message["CustomID"] = f"Async-Exhaustive-Telemetry-{uuid.uuid4().hex[:8]}"

            payload = {"Messages": [message], "SandboxMode": True}

            resp = await client_v31.send.create(data=payload)
            assert resp.status_code == 200
            assert "Messages" in resp.json()

    asyncio.run(_run())


def test_live_template_content_builder_exhaustive() -> None:
    """Integration test hitting all options of TemplateContentBuilder via AsyncClient."""

    async def _run() -> None:
        template_name = f"Async_Exhaustive_Tpl_{uuid.uuid4().hex[:8]}"
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            create_resp = await client_live.template.create(
                data={
                    "Name": template_name,
                    "Author": "Exhaustive Async CI",
                    "EditMode": 1,
                    "Purposes": ["transactional"],
                }
            )
            assert create_resp.status_code == 201
            template_id = create_resp.json()["Data"][0]["ID"]

            try:
                builder = TemplateContentBuilder()
                builder.set_meta(author="Async CI Runner", name="Override Name", locale="fr_FR")
                builder.set_headers({"Subject": "Async Template Content Subject"})
                builder.set_content(
                    text="Template plain text.",
                    html="<div>Template HTML content</div>",
                    mjml="<mjml><mj-body><mj-text>Hello</mj-text></mj-body></mjml>",
                )
                content_payload = builder.build()

                content_resp = await client_live.template_detailcontent.create(id=template_id, data=content_payload)
                assert content_resp.status_code in (200, 201)
            finally:
                await client_live.template.delete(id=template_id)

    asyncio.run(_run())


def test_live_custom_headers_propagation() -> None:
    """Verify that custom headers pass cleanly through async endpoint operations."""

    async def _run() -> None:
        custom_headers = {"X-Request-Source": "Async-CI-Runner", "X-Integration-Test": "True"}
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            resp = await client_live.contact.get(filters={"limit": 1}, headers=custom_headers)
            assert resp.status_code == 200

    asyncio.run(_run())


def test_live_stream_with_parse_qs_filters() -> None:
    """Verify AsyncEndpoint.stream correctly casts multidicts from parse_qs during live pagination."""

    async def _run() -> None:
        query_filters = parse_qs("offset=0&limit=2")
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            items = []
            async for item in client_live.contact.stream(filters=query_filters, chunk_size=2):
                items.append(item)
                if len(items) >= 2:
                    break

            assert isinstance(items, list)
            if items:
                assert "ID" in items[0]

    asyncio.run(_run())


def test_live_account_metadata_endpoints() -> None:
    """Verify live read-only access to account and configuration endpoints via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            resp_meta = await client_live.contactmetadata.get(filters={"limit": 1})
            assert resp_meta.status_code == 200
            assert "Data" in resp_meta.json()

            resp_dns = await client_live.dns.get(filters={"limit": 1})
            assert resp_dns.status_code == 200
            assert "Data" in resp_dns.json()

            resp_key = await client_live.apikey.get(filters={"limit": 1})
            assert resp_key.status_code == 200

    asyncio.run(_run())


def test_live_event_statistics_endpoints() -> None:
    """Verify real-time event tracking and statistics log retrieval via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            for stats_endpoint in (
                "bouncestatistics",
                "clickstatistics",
                "openinformation",
                "toplinkclicked",
                "useragentstatistics",
            ):
                endpoint = getattr(client_live, stats_endpoint)
                resp = await endpoint.get(filters={"limit": 1})
                assert resp.status_code == 200
                assert "Data" in resp.json()

    asyncio.run(_run())


def test_live_eventcallbackurl_crud_lifecycle() -> None:
    """End-to-End test for webhook (eventcallbackurl) management using click EventType to avoid sync collision."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            existing = await client_live.eventcallbackurl.get(filters={"EventType": "click", "IsBackup": False})
            if existing.status_code == 200 and existing.json().get("Data"):
                for item in existing.json()["Data"]:
                    await client_live.eventcallbackurl.delete(id=item["ID"])

            webhook_url = f"https://example.com/async_webhook_{uuid.uuid4().hex[:8]}"

            create_resp = await client_live.eventcallbackurl.create(
                data={
                    "EventType": "click",
                    "Url": webhook_url,
                    "Status": "alive",
                    "IsBackup": False,
                }
            )
            if create_resp.status_code != 201:
                pytest.skip(f"Webhook setup not permitted: {create_resp.text}")

            webhook_id = create_resp.json()["Data"][0]["ID"]

            try:
                get_resp = await client_live.eventcallbackurl.get(id=webhook_id)
                assert get_resp.status_code == 200
                assert get_resp.json()["Data"][0]["Url"] == webhook_url

                update_resp = await client_live.eventcallbackurl.update(
                    id=webhook_id,
                    data={"Status": "dead"},
                )
                assert update_resp.status_code == 200
            finally:
                await client_live.eventcallbackurl.delete(id=webhook_id)

    asyncio.run(_run())


def test_live_statistics_link_click_and_recipient_esp() -> None:
    """Verify live read queries on statistics/link-click and statistics/recipient-esp via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            try:
                resp_click = await client_live.statistics_linkClick.get(filters={"CampaignID": 1})
                assert resp_click.status_code in (200, 404)
                if resp_click.status_code == 200:
                    assert "Data" in resp_click.json()
            except (DoesNotExistError, ValidationError) as e:
                assert getattr(e, "status_code", 404) in (400, 404)

            try:
                resp_esp = await client_live.statistics_recipientEsp.get(filters={"CampaignID": 1})
                assert resp_esp.status_code in (200, 404)
                if resp_esp.status_code == 200:
                    assert "Data" in resp_esp.json()
            except (DoesNotExistError, ValidationError) as e:
                assert getattr(e, "status_code", 404) in (400, 404)

    asyncio.run(_run())


def test_live_contact_subresources_and_actions() -> None:
    """Verify live URI interpolation on multi-segment contact sub-resources via AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=get_live_auth(), version="v3") as client_live:
            test_email = f"async-ci-subresource-{uuid.uuid4().hex[:8]}@example.com"
            create_contact = await client_live.contact.create(data={"Email": test_email})
            if create_contact.status_code != 201:
                pytest.skip(f"Contact creation failed: {create_contact.text}")

            contact_id = create_contact.json()["Data"][0]["ID"]

            list_name = f"Async_CI_List_{uuid.uuid4().hex[:8]}"
            create_list = await client_live.contactslist.create(data={"Name": list_name})
            if create_list.status_code != 201:
                with contextlib.suppress(MailjetAuthError):
                    await client_live.contact.delete(id=contact_id)
                pytest.skip(f"ContactsList creation failed: {create_list.text}")

            list_id = create_list.json()["Data"][0]["ID"]

            try:
                sub_payload = {"ContactsLists": [{"ListID": list_id, "Action": "addnoforce"}]}
                resp_manage = await client_live.contact_managecontactslists.create(
                    id=contact_id,
                    data=sub_payload,
                )
                assert resp_manage.status_code in (200, 201)

                resp_getlists = await client_live.contact_getcontactslists.get(id=contact_id)
                assert resp_getlists.status_code == 200
                assert "Data" in resp_getlists.json()

                many_payload = {
                    "Action": "addnoforce",
                    "Contacts": [{"Email": test_email}],
                }
                resp_many = await client_live.contactslist_managemanycontacts.create(
                    id=list_id,
                    data=many_payload,
                )
                assert resp_many.status_code in (200, 201)

            finally:
                with contextlib.suppress(MailjetAuthError):
                    await client_live.contact.delete(id=contact_id)

                with contextlib.suppress(MailjetAuthError, DoesNotExistError):
                    await client_live.contactslist.delete(id=list_id)

    asyncio.run(_run())
