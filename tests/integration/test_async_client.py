"""Asynchronous live integration tests for AsyncClient and AsyncEndpoint."""

from __future__ import annotations

import asyncio
import os
import uuid
import warnings
from urllib.parse import parse_qs

import pytest

from mailjet_rest import MailjetAuthError
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import DoesNotExistError, ValidationError


# Safety guard: Prevent live integration tests from running if credentials or httpx2 are missing
pytestmark = [
    pytest.mark.skipif(
        "MJ_APIKEY_PUBLIC" not in os.environ or "MJ_APIKEY_PRIVATE" not in os.environ,
        reason="MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set.",
    ),
    pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed."),
]


def _get_auth() -> tuple[str, str]:
    """Return live Mailjet API credentials from environment."""
    return (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])


def test_async_live_send_api_v3_1_sandbox_and_builders() -> None:
    """Test AsyncClient Send API v3.1 happy path using MessageBuilder, SendPayloadBuilder, and SandboxMode."""

    async def _run() -> None:
        async with AsyncClient(auth=_get_auth(), version="v3.1", timeout=(5.0, 20.0)) as aclient:
            msg_builder = (
                MessageBuilder()
                .set_sender("pilot@mailjet.com", "Async Mailjet Pilot")
                .add_recipient("passenger1@mailjet.com", "Async Passenger 1")
                .set_subject("Async CI/CD Sandbox Test")
                .set_content(text="Async test body", html="<h3>Async test {{var:name}}</h3>")
                .set_variables({"name": "Async Traveller"})
            )
            payload = (
                SendPayloadBuilder()
                .set_sandbox_mode(True)
                .set_globals({"CustomCampaign": "async-ci"})
                .add_message(msg_builder)
                .build()
            )
            payload["Messages"][0]["TemplateLanguage"] = True
            payload["Messages"][0]["CustomID"] = "Async-Integration-123"

            result = await aclient.send.create(data=payload)
            assert result.status_code in {200, 400, 401}
            assert result.status_code != 404

    asyncio.run(_run())


def test_async_live_contact_and_template_crud_lifecycle() -> None:
    """Test AsyncClient end-to-end CRUD lifecycle for contacts and v3 templates."""

    async def _run() -> None:
        async with AsyncClient(auth=_get_auth(), version="v3") as aclient:
            assert isinstance(aclient.contact, AsyncEndpoint)
            assert "AsyncClient" in repr(aclient)
            assert "Mailjet AsyncClient" in str(aclient)

            aclient.config.dry_run = True
            dry_res = await aclient.contact.create(data={"Email": "dryrun-async@example.com"})
            assert dry_res.status_code == 200
            aclient.config.dry_run = False

            test_email = f"async-ci-contact-{uuid.uuid4().hex[:8]}@example.com"
            c_resp = await aclient.contact.create(data={"Email": test_email, "IsExcludedFromCampaigns": "true"})
            assert c_resp.status_code == 201
            contact_id = c_resp.json()["Data"][0]["ID"]

            try:
                g_resp = await aclient.contact.get(id=contact_id, headers={"X-Async-Test": "true"})
                assert g_resp.status_code == 200
                assert g_resp.json()["Data"][0]["Email"] == test_email

                u_resp = await aclient.contact.update(id=contact_id, data={"Name": "Async CI User"})
                assert u_resp.status_code == 200
            finally:
                try:
                    d_resp = await aclient.contact.delete(id=contact_id)
                    assert d_resp.status_code in {200, 204}
                except MailjetAuthError as e:
                    assert e.status_code == 401

            tpl_name = f"Async_CI_Template_{uuid.uuid4().hex[:8]}"
            t_resp = await aclient.template.create(
                data={
                    "Name": tpl_name,
                    "Author": "Async CI",
                    "EditMode": 1,
                    "Purposes": ["transactional"],
                }
            )
            if t_resp.status_code == 201:
                tpl_id = t_resp.json()["Data"][0]["ID"]
                try:
                    content_payload = (
                        TemplateContentBuilder()
                        .set_meta(author="Async CI", name=tpl_name, locale="en_US")
                        .set_headers({"Subject": "Async Subject"})
                        .set_content(text="Async Text", html="<h1>Async HTML</h1>")
                        .build()
                    )
                    tc_resp = await aclient.template_detailcontent.create(id=tpl_id, data=content_payload)
                    assert tc_resp.status_code in {200, 201}

                    tg_resp = await aclient.template_detailcontent.get(id=tpl_id)
                    assert tg_resp.status_code == 200
                finally:
                    await aclient.template.delete(id=tpl_id)

    asyncio.run(_run())


def test_async_live_content_api_v1_lifecycle() -> None:
    """Test AsyncClient against v1 Content API template lock/unlock/publish routes."""

    async def _run() -> None:
        async with AsyncClient(auth=_get_auth(), version="v1") as aclient_v1:
            tpl_data = {
                "Name": f"async-v1-tpl-{uuid.uuid4().hex[:8]}",
                "EditMode": 2,
                "Purposes": ["transactional"],
            }
            create_resp = await aclient_v1.templates.create(data=tpl_data)
            if create_resp.status_code != 201:
                pytest.skip(f"Could not create v1 template: {create_resp.text}")

            tpl_id = create_resp.json()["Data"][0]["ID"]
            try:
                content_data = {
                    "Headers": {"Subject": "Async V1 Subject"},
                    "HtmlPart": "<html><body><h1>Async V1</h1></body></html>",
                    "TextPart": "Async V1",
                    "Locale": "en_US",
                }
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    c_resp = await aclient_v1.templates_contents.create(id=tpl_id, data=content_data)
                assert c_resp.status_code == 201

                pub_resp = await aclient_v1.templates_contents_publish.create(id=tpl_id)
                assert pub_resp.status_code == 200

                type_resp = await aclient_v1.templates_contents_types.get(id=tpl_id, action_id="P")
                assert type_resp.status_code == 200
            finally:
                await aclient_v1.templates.delete(id=tpl_id)

    asyncio.run(_run())


def test_async_live_stream_pagination_and_errors() -> None:
    """Test AsyncEndpoint.stream() pagination and live error mapping on AsyncClient."""

    async def _run() -> None:
        async with AsyncClient(auth=_get_auth(), version="v3") as aclient:
            query_filters = parse_qs("offset=0&limit=2")
            contacts = []
            async for item in aclient.contact.stream(filters=query_filters, chunk_size=2):
                contacts.append(item)
                if len(contacts) >= 3:
                    break
            assert isinstance(contacts, list)

            with pytest.raises(ValidationError) as exc_val:
                await aclient.sender.create(data={})
            assert exc_val.value.status_code == 400

            with pytest.raises((DoesNotExistError, ValidationError)) as exc_404:
                await aclient.template_detailcontent.get(id=999999999999)
            assert exc_404.value.status_code in {400, 404}

        bearer_client = AsyncClient(auth="invalid_bearer_token_xyz", version="v1")
        try:
            with pytest.raises(MailjetAuthError) as exc_auth:
                await bearer_client.templates.get()
            assert exc_auth.value.status_code == 401
        finally:
            await bearer_client.close()

    asyncio.run(_run())
