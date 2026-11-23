"""Offline loopback TLS 1.2+ parity integration tests for AsyncClient with builders, uploads, and telemetry."""

from __future__ import annotations

import asyncio
import base64
import io
import json
import logging
from pathlib import Path
from typing import Any

import pytest

from mailjet_rest import AsyncClient, Config, ValidationError
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.client import _httpx2
from tests.integration.local_loopback._servers import _IntegrationHTTPSServer, _ListHandler


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed.")


def test_async_message_builder_full_features_and_real_tls_dispatch(
    builders_tls_server: dict[str, Any], tmp_path: Path
) -> None:
    """Build rich Send v3.1 payloads with attachments/CIDs/headers and dispatch via AsyncClient over loopback TLS."""
    server: _IntegrationHTTPSServer = builders_tls_server["server"]
    server.recorded_requests.clear()
    url: str = builders_tls_server["url"]
    ca_path: Path = builders_tls_server["ca_path"]

    txt_file = tmp_path / "async_summary.txt"
    txt_file.write_bytes(b"Async attachment payload")
    png_file = tmp_path / "async_logo.png"
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00"
    png_file.write_bytes(png_bytes)

    msg_builder = (
        MessageBuilder()
        .set_sender("sender@bücher.example", "Async Sender")
        .add_recipient("to@example.com", "Async To")
        .add_cc("cc@example.com", "Async CC")
        .add_bcc("bcc@example.com")
        .set_reply_to("reply@example.com", "Async Reply")
        .set_subject("Async Integration Dispatch")
        .set_custom_id("async-order-456")
        .set_event_payload("async-evt-xyz")
        .set_tracking(opens="enabled", clicks="disabled")
        .set_headers({"X-Async-Trace": "ok"})
        .set_list_unsubscribe(
            "https://example.com/unsub",
            mailto_address="unsub@bücher.example",
            one_click=True,
        )
        .set_content(text="Async plain", html='<p>Async <img src="cid:async-logo-1"/></p>')
        .set_template(777, language_active=True)
        .set_variables({"nested": {"k": "v"}})
        .attach_file(txt_file, base_dir=tmp_path)
        .attach_inline(png_file, base_dir=tmp_path, content_id="<async-logo-1>")
    )

    built_msg_d: dict[str, Any] = dict(msg_builder.build())
    assert built_msg_d["From"] == {"Email": "sender@xn--bcher-kva.example", "Name": "Async Sender"}
    assert built_msg_d["Attachments"][0]["ContentType"] == "text/plain"
    assert built_msg_d["InlinedAttachments"][0]["ContentID"] == "async-logo-1"
    assert base64.b64decode(built_msg_d["InlinedAttachments"][0]["Base64Content"]) == png_bytes

    payload = (
        SendPayloadBuilder()
        .add_message(msg_builder)
        .set_sandbox_mode(True)
        .set_globals({"From": {"Email": "global@example.com"}})
        .build()
    )
    payload_d: dict[str, Any] = dict(payload)
    assert payload_d["SandboxMode"] is True
    assert payload_d["Globals"] == {"From": {"Email": "global@example.com"}}

    err_msg = (
        MessageBuilder()
        .set_sender("err@example.com")
        .add_recipient("to@example.com")
        .set_custom_id("trigger-400")
        .set_content(text="Fail")
        .build()
    )
    err_payload = SendPayloadBuilder().add_message(err_msg).build()

    async def _run() -> None:
        async with AsyncClient(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as ac:
            resp = await ac.send_v31.create(data=payload)
            assert resp.status_code == 200
            assert resp.json()["Messages"][0]["Status"] == "success"

            with pytest.raises(ValidationError, match="Simulated send failure"):
                await ac.send_v31.create(data=err_payload)

    asyncio.run(_run())

    wire = server.recorded_requests[-2]
    assert wire["path"] == "/v3.1/send"
    wire_json = json.loads(wire["body"].decode("utf-8"))
    assert wire_json["SandboxMode"] is True
    assert wire_json["Messages"][0]["CustomID"] == "async-order-456"


def test_async_template_content_builder_and_real_tls_dispatch(builders_tls_server: dict[str, Any]) -> None:
    """Exercise TemplateContentBuilder guarded metadata/content variants dispatched over AsyncClient TLS."""
    url: str = builders_tls_server["url"]
    ca_path: Path = builders_tls_server["ca_path"]

    class _GuardedTemplateBuilder(TemplateContentBuilder):
        ENABLE_SPAM_GUARD = True

    tpl = (
        _GuardedTemplateBuilder()
        .set_meta(author="Async Alice", name="AsyncWelcome", locale="uk_UA")
        .set_headers({"Reply-To": "help@example.com"})
        .set_content(text="Hello Async", html="<p>Hello Async</p>", mjml="<mjml><mj-body/></mjml>")
        .build()
    )
    assert tpl["Author"] == "Async Alice"
    assert tpl["Name"] == "AsyncWelcome"
    assert tpl["Locale"] == "uk_UA"

    async def _run() -> None:
        async with AsyncClient(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as ac:
            resp = await ac.template_detailcontent.create(id=42, data=tpl)
            assert resp.status_code == 201
            assert resp.json()["Data"][0]["Name"] == "AsyncWelcome"

    asyncio.run(_run())


def test_async_client_builders_telemetry_and_redacting_filter(builders_tls_server: dict[str, Any]) -> None:
    """Exercise AsyncClient sending builder payloads with DEBUG telemetry and RedactingFilter attached."""
    url: str = builders_tls_server["url"]
    ca_path: Path = builders_tls_server["ca_path"]

    msg = (
        MessageBuilder()
        .set_sender("async@example.com")
        .add_recipient("to@example.com")
        .set_custom_id("async-cid 1")
        .set_template(888, language_active=False)
        .build()
    )
    payload = SendPayloadBuilder().add_message(msg).set_sandbox_mode(False).build()
    assert "SandboxMode" not in payload

    tpl_payload = (
        TemplateContentBuilder()
        .set_meta(author="Async Author", name="AsyncTpl", locale="en_US")
        .set_headers({"X-Tpl": "async"})
        .set_content(text="Async tpl text", html="<p>Async</p>", mjml="<mjml><mj-body/></mjml>")
        .build()
    )

    client_logger = logging.getLogger("mailjet_rest.client")
    old_level = client_logger.level
    capture = _ListHandler()
    client_logger.addHandler(capture)
    client_logger.setLevel(logging.DEBUG)

    async def _run() -> None:
        async with AsyncClient(
            auth="secret_bearer_token", config=Config(api_url=url, verify=ca_path, max_retries=0)
        ) as ac:
            r1 = await ac.send_v31.create(data=payload)
            assert r1.status_code == 200
            r2 = await ac.template_detailcontent.create(id=55, data=tpl_payload)
            assert r2.status_code == 201
            client_logger.debug("Header check Authorization: Bearer leaked_tok api_key=my_secret_key")

    try:
        asyncio.run(_run())
    finally:
        client_logger.removeHandler(capture)
        client_logger.setLevel(old_level)

    rendered = [rec.getMessage() for rec in capture.records]
    assert any("CustomID=async-cid_1" in m and "TemplateID=888" in m for m in rendered)
    assert any("Authorization: Bearer ********" in m and "api_key=********" in m for m in rendered)
    assert not any("leaked_tok" in m or "my_secret_key" in m for m in rendered)


def test_async_multipart_upload_and_crlf_guardrails(builders_tls_server: dict[str, Any]) -> None:
    """Verify AsyncClient multipart data_images uploads and pre-flight CRLF/NUL filename rejection over TLS."""
    server: _IntegrationHTTPSServer = builders_tls_server["server"]
    server.recorded_requests.clear()
    url: str = builders_tls_server["url"]
    ca_path: Path = builders_tls_server["ca_path"]

    async def _run() -> None:
        async with AsyncClient(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as ac:
            up = await ac.data_images.create(
                headers={"Content-Type": None},
                files=[("file", ("logo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png", {"X-Tag": "ok"}))],
            )
            assert up.status_code == 201
            assert "multipart/form-data" in up.json()["Data"][0]["content_type"]

            with pytest.raises(ValueError, match="CRLF or NUL"):
                await ac.data_images.create(files={"file": ("evil\r\n.png", io.BytesIO(b"x"), "image/png")})

    asyncio.run(_run())
    assert server.recorded_requests[-1]["path"] == "/v1/data/images"
    assert "multipart/form-data" in server.recorded_requests[-1]["headers"]["content-type"]
