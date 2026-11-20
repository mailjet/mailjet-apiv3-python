"""Offline loopback TLS 1.2+ and real-filesystem integration tests for builders and security modules."""

from __future__ import annotations

import asyncio
import base64
import errno
import http.server
import io
import ipaddress
import json
import logging
import os
import shutil
import ssl
import subprocess
import threading
from collections.abc import Generator, Iterator, Mapping
from pathlib import Path
from types import MappingProxyType, SimpleNamespace
from typing import Any, NamedTuple, cast

import pytest

from mailjet_rest import AsyncClient, Client, Config, ValidationError
from mailjet_rest.builders import (
    ChunkedStreamer,
    MessageBuilder,
    SendPayloadBuilder,
    TemplateContentBuilder,
    _clone_message_payload,
)
from mailjet_rest.client import _httpx2
from mailjet_rest.utils import filesystem_security, guardrails as guardrails_mod, html_guard, telemetry
from mailjet_rest.utils.guardrails import RedactingFilter, SecretAuth, SecurityGuard


class _IntegrationTLSHandler(http.server.BaseHTTPRequestHandler):
    """Thread-safe local HTTPS stub verifying built payloads, headers, and multipart uploads."""

    @property
    def _tls_server(self) -> _IntegrationHTTPSServer:
        return cast("_IntegrationHTTPSServer", self.server)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def _record(self, method: str, body: bytes) -> None:
        self._tls_server.recorded_requests.append(
            {
                "method": method,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )

    def do_GET(self) -> None:
        body = self._read_body()
        self._record("GET", body)
        self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 1}]})

    def do_POST(self) -> None:
        body = self._read_body()
        self._record("POST", body)

        if self.path.startswith("/v3.1/send"):
            parsed = json.loads(body.decode("utf-8"))
            first_msg = parsed["Messages"][0] if parsed.get("Messages") else {}
            custom_id = first_msg.get("CustomID", "")
            if custom_id == "trigger-400":
                self._write_json(
                    400,
                    {"Messages": [{"Errors": [{"ErrorMessage": "Simulated send failure"}]}]},
                )
                return
            self._write_json(
                200,
                {
                    "Messages": [
                        {
                            "Status": "success",
                            "CustomID": custom_id,
                            "To": [
                                {
                                    "Email": "to@example.com",
                                    "MessageUUID": "uuid-loopback-1",
                                    "MessageID": 1001,
                                    "MessageHref": "https://api.mailjet.com/v3/REST/message/1001",
                                }
                            ],
                        }
                    ]
                },
            )
            return

        if self.path.startswith("/v3/REST/template/"):
            parsed = json.loads(body.decode("utf-8"))
            self._write_json(201, {"Count": 1, "Data": [parsed]})
            return

        if self.path.startswith("/v1/data/images"):
            ctype = self.headers.get("Content-Type", "")
            self._write_json(201, {"Count": 1, "Data": [{"ID": "img-1", "content_type": ctype}]})
            return

        self._write_json(201, {"Count": 1, "Data": [{"ID": 100}]})


class _IntegrationHTTPSServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address, _IntegrationTLSHandler)
        self.recorded_requests: list[dict[str, Any]] = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


def _generate_self_signed_cert(cert_dir: Path, name: str) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary not available for loopback TLS integration test")
    assert openssl is not None
    cert_path = cert_dir / f"{name}.pem"
    key_path = cert_dir / f"{name}.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return cert_path, key_path


@pytest.fixture(scope="module")
def local_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback HTTPS TLS 1.2+ server for builders and security integration."""
    cert_dir = tmp_path_factory.mktemp("tls_builders_security")
    cert_path, key_path = _generate_self_signed_cert(cert_dir, "server")
    server = _IntegrationHTTPSServer(("localhost", 0), cert_path, key_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"https://localhost:{port}/",
            "ca_path": cert_path,
            "server": server,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


class _BytesPathLike:
    def __init__(self, path_bytes: bytes) -> None:
        self._path_bytes = path_bytes

    def __fspath__(self) -> bytes:
        return self._path_bytes


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _SecretPair(NamedTuple):
    token: str
    note: str


class _ModelDumpObj:
    def model_dump(self) -> dict[str, Any]:
        return {
            "api_key": "secret-key-val",  # pragma: allowlist secret
            "label": "Authorization: Bearer tok_from_model",
        }


class _DictObj:
    def __init__(self) -> None:
        self.password = "pw-secret"  # pragma: allowlist secret
        self.details = "api_secret=my_secret_val"


class _SlotsObj:
    __slots__ = ("val",)

    def __init__(self, val: str) -> None:
        self.val = val

    def __str__(self) -> str:
        return self.val


class _BrokenStrSlotsObj:
    __slots__ = ()

    def __str__(self) -> str:
        raise RuntimeError("cannot stringify")


class _BrokenMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("broken mapping")

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 1

    def get(self, key: str, default: Any = None) -> Any:
        raise RuntimeError("broken mapping get")


def test_message_builder_full_features_and_real_tls_dispatch(local_tls_server: dict[str, Any], tmp_path: Path) -> None:
    """Build rich Send v3.1 messages with attachments/CIDs/headers/tracking and dispatch over loopback TLS."""
    server: _IntegrationHTTPSServer = local_tls_server["server"]
    server.recorded_requests.clear()
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]

    txt_file = tmp_path / "summary.txt"
    txt_file.write_bytes(b"Summary attachment payload")
    bin_file = tmp_path / "payload.unknown_ext_xyz"
    bin_file.write_bytes(b"\x01\x02\x03\x04")
    png_file = tmp_path / "logo.png"
    png_bytes = b"\x89PNG\r\n\x1a\n\x00\x00"
    png_file.write_bytes(png_bytes)

    orig_vars: dict[str, Any] = {"nested": {"k": "v"}, "arr": [1, (2, 3), True, None]}
    msg_builder = (
        MessageBuilder()
        .set_sender("sender@bücher.example", "Sender Name")
        .add_recipient("to@example.com", "To Name")
        .add_cc("cc@example.com", "CC Name")
        .add_bcc("bcc@example.com")
        .set_reply_to("reply@example.com", "Reply Name")
        .set_subject("Integration Dispatch")
        .set_custom_id("order-123")
        .set_event_payload("evt-abc")
        .set_tracking(opens="enabled", clicks="disabled")
        .set_headers({"X-Trace": "ok", "X-Tab": "a\tb"})
        .set_list_unsubscribe(
            "https://example.com/unsub",
            mailto_address="unsub@bücher.example",
            one_click=True,
        )
        .set_content(text="Plain body", html='<p>Hello <img src="cid:logo-1"/><img src="cid:logo.png"/></p>')
        .set_template(777, language_active=True)
        .set_variables(orig_vars)
        .attach_file(txt_file, base_dir=tmp_path)
        .attach_file(bin_file, base_dir=tmp_path)
        .attach_file(txt_file, content_type="text/csv", base_dir=tmp_path)
        .attach_inline(png_file, base_dir=tmp_path, content_id="<logo-1>")
        .attach_inline(png_file, content_type="image/png", base_dir=tmp_path)
    )
    orig_vars["nested"]["k"] = "mutated"

    built_msg = msg_builder.build()
    built_msg_d: dict[str, Any] = dict(built_msg)
    assert built_msg_d["From"] == {"Email": "sender@xn--bcher-kva.example", "Name": "Sender Name"}
    assert built_msg_d["To"] == [{"Email": "to@example.com", "Name": "To Name"}]
    assert built_msg_d["Cc"] == [{"Email": "cc@example.com", "Name": "CC Name"}]
    assert built_msg_d["Bcc"] == [{"Email": "bcc@example.com"}]
    assert built_msg_d["ReplyTo"] == {"Email": "reply@example.com", "Name": "Reply Name"}
    assert built_msg_d["CustomID"] == "order-123"
    assert built_msg_d["EventPayload"] == "evt-abc"
    assert built_msg_d["TrackOpens"] == "enabled"
    assert built_msg_d["TrackClicks"] == "disabled"
    assert built_msg_d["TemplateID"] == 777
    assert built_msg_d["TemplateLanguage"] is True
    assert built_msg_d["Variables"]["nested"]["k"] == "v"
    assert built_msg_d["Headers"]["List-Unsubscribe"] == (
        "<https://example.com/unsub>, <mailto:unsub@xn--bcher-kva.example>"
    )
    assert built_msg_d["Headers"]["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert built_msg_d["Attachments"][0]["ContentType"] == "text/plain"
    assert built_msg_d["Attachments"][1]["ContentType"] == "application/octet-stream"
    assert built_msg_d["Attachments"][2]["ContentType"] == "text/csv"
    assert built_msg_d["InlinedAttachments"][0]["ContentID"] == "logo-1"
    assert built_msg_d["InlinedAttachments"][1]["ContentID"] == "logo.png"
    assert base64.b64decode(built_msg_d["InlinedAttachments"][0]["Base64Content"]) == png_bytes

    # Exercise raw dict message with MappingProxyType Headers and optional metadata fields
    msg_no_one_click = (
        MessageBuilder()
        .set_sender("minimal@example.com")
        .add_recipient("rec@example.com")
        .set_list_unsubscribe("https://example.com/optout", one_click=False)
        .set_content(text=None, html="<p>Only HTML</p>")
        .set_tracking()
        .build()
    )
    msg_no_one_click_d: dict[str, Any] = dict(msg_no_one_click)
    assert "List-Unsubscribe-Post" not in msg_no_one_click_d["Headers"]
    assert "TextPart" not in msg_no_one_click_d

    raw_dict_msg: dict[str, Any] = {
        "From": {"Email": "raw@example.com"},
        "To": [{"Email": "dest@example.com"}],
        "Subject": "Raw metadata",
        "TextPart": "Raw text",
        "Priority": 2,
        "CustomCampaign": "camp-1",
        "DeduplicateCampaign": True,
        "URLTags": "utm_source=sdk",
        "TemplateErrorReporting": {"Email": "err@example.com"},
        "TemplateErrorDeliver": False,
        "Headers": {"X-Immutable": "yes"},
    }
    cloned_proxy_d: dict[str, Any] = dict(
        _clone_message_payload(
            {"From": {"Email": "raw@example.com"}, "Headers": MappingProxyType({"X-Immutable": "yes"})}
        )
    )
    assert cloned_proxy_d["Headers"]["X-Immutable"] == "yes"

    payload = (
        SendPayloadBuilder()
        .add_message(msg_builder)
        .add_message(cast("Any", msg_no_one_click))
        .add_message(cast("Any", raw_dict_msg))
        .set_sandbox_mode(True)
        .set_globals({"From": {"Email": "global@example.com"}})
        .build()
    )
    payload_d: dict[str, Any] = dict(payload)
    assert payload_d["SandboxMode"] is True
    assert payload_d["Globals"] == {"From": {"Email": "global@example.com"}}
    assert len(payload_d["Messages"]) == 3

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        resp = client.send_v31.create(data=payload)
        assert resp.status_code == 200
        assert resp.json()["Messages"][0]["Status"] == "success"

    wire = server.recorded_requests[-1]
    assert wire["path"] == "/v3.1/send"
    wire_json = json.loads(wire["body"].decode("utf-8"))
    assert wire_json["SandboxMode"] is True
    assert wire_json["Messages"][0]["CustomID"] == "order-123"
    assert wire_json["Messages"][2]["URLTags"] == "utm_source=sdk"


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_builders_telemetry_and_redacting_filter(local_tls_server: dict[str, Any]) -> None:
    """Exercise AsyncClient sending builder payloads with DEBUG telemetry and RedactingFilter attached."""
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]

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


def test_template_content_builder_and_real_tls_dispatch(local_tls_server: dict[str, Any]) -> None:
    """Exercise TemplateContentBuilder metadata, content variants, deprecation warning, and TLS dispatch."""
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml"):
        empty_tpl = TemplateContentBuilder().set_meta().set_content().build()
    assert empty_tpl == {}

    class _GuardedTemplateBuilder(TemplateContentBuilder):
        ENABLE_SPAM_GUARD = True

    with pytest.raises(ValueError, match="Javascript/XSS"):
        _GuardedTemplateBuilder().set_content(html="<script>alert(1)</script>")

    tpl = (
        _GuardedTemplateBuilder()
        .set_meta(author="Alice", name="Welcome", locale="uk_UA")
        .set_headers({"Reply-To": "help@example.com"})
        .set_content(text="Hello", html="<p>Hello</p>", mjml="<mjml><mj-body/></mjml>")
        .build()
    )
    assert tpl["Author"] == "Alice"
    assert tpl["Name"] == "Welcome"
    assert tpl["Locale"] == "uk_UA"
    assert tpl["Text-part"] == "Hello"
    assert tpl["Html-part"] == "<p>Hello</p>"
    assert tpl["MJMLContent"] == "<mjml><mj-body/></mjml>"

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        resp = client.template_detailcontent.create(id=42, data=tpl)
        assert resp.status_code == 201
        assert resp.json()["Data"][0]["Name"] == "Welcome"


def test_builders_validation_warnings_spam_guard_and_limits(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify builder error branches, Gmail 102KB clip & CID warnings, SpamGuard, and size/count caps."""

    class _GuardedMessageBuilder(MessageBuilder):
        ENABLE_SPAM_GUARD = True

    # SpamGuard safe HTML, XSS error, and deliverability warning branch
    _GuardedMessageBuilder().set_content(html="<p>Clean body</p>")
    with pytest.raises(ValueError, match="Javascript/XSS"):
        _GuardedMessageBuilder().set_content(html="<script>evil()</script>")

    monkeypatch.setattr(
        SecurityGuard,
        "analyze_html_safety",
        staticmethod(lambda _html: {"is_safe": False, "issues": ["Suspicious link marker"]}),
    )
    with pytest.warns(UserWarning, match="Deliverability Warning"):
        _GuardedMessageBuilder().set_content(html="<p>Warn</p>")
    monkeypatch.undo()

    # Gmail 102KB clip warning + CID checks (case-insensitive CID:, colon without cid:, empty cid:, matched cid)
    big_html = "<p>" + ("a" * (MessageBuilder.GMAIL_CLIP_BYTES + 128)) + "</p>"
    with pytest.warns(UserWarning, match="Gmail 102 KB clip"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(html=big_html).build()

    with pytest.warns(UserWarning, match="Inline CID references missing"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
            html='<img src="CID:missing_logo"/>'
        ).build()

    # Colons without cid: and cid: without identifier must NOT warn
    MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
        html='<a href="https://example.com">link</a><span>cid: </span>'
    ).build()

    # HTMLPart between 25KB and 102KB passes without clip warning
    medium_html = "<p>" + ("x" * (MessageBuilder.GMAIL_CLIP_BYTES // 3)) + "</p>"
    MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(html=medium_html).build()

    # Required fields validation + Cc-only / Bcc-only / TemplateID-only paths
    with pytest.raises(ValueError, match="Sender"):
        MessageBuilder().add_recipient("r@example.com").set_content(text="hi").build()
    with pytest.raises(ValueError, match="At least one recipient"):
        MessageBuilder().set_sender("s@example.com").set_content(text="hi").build()
    with pytest.raises(ValueError, match="TextPart, HTMLPart, or TemplateID"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").build()

    MessageBuilder().set_sender("s@example.com").add_cc("cc@example.com").set_template(10).build()
    MessageBuilder().set_sender("s@example.com").add_bcc("bcc@example.com").set_content(text="ok").build()

    # Part size limits (Variables > 1MB, HTMLPart > 5MB, TextPart > 5MB, and TextPart 1.5MB valid)
    with pytest.raises(ValueError, match="Variables payload too large"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
            text="hi"
        ).set_variables({"blob": "x" * (1024 * 1024 + 50)}).build()

    with pytest.raises(ValueError, match="HTMLPart exceeds 5MB"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
            html="a" * (MessageBuilder.MAX_PART_SIZE + 10)
        ).build()

    with pytest.raises(ValueError, match="TextPart exceeds 5MB"):
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
            text="a" * (MessageBuilder.MAX_PART_SIZE + 10)
        ).build()

    MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(
        text="a" * (MessageBuilder.MAX_PART_SIZE // 2)
    ).build()

    # Method-level validation errors
    with pytest.raises(TypeError, match="expected str"):
        MessageBuilder().set_subject(cast("Any", 123))
    with pytest.raises(ValueError, match="forbidden control characters"):
        MessageBuilder().set_subject("Bad\r\nSubject")
    with pytest.raises(ValueError, match="forbidden control characters"):
        MessageBuilder().set_custom_id("cid\n")
    with pytest.raises(ValueError, match="forbidden control characters"):
        MessageBuilder().set_event_payload("ev\x00")
    for bad_email in ("no-at", "a b@example.com", "@example.com", "user@"):
        with pytest.raises(ValueError, match="Invalid email"):
            MessageBuilder().set_sender(bad_email)

    with pytest.raises(ValueError, match="Invalid TrackOpens"):
        MessageBuilder().set_tracking(opens=cast("Any", "invalid"))
    with pytest.raises(ValueError, match="Invalid TrackClicks"):
        MessageBuilder().set_tracking(clicks=cast("Any", "invalid"))

    with pytest.raises(ValueError, match="angle brackets"):
        MessageBuilder().set_list_unsubscribe("<https://example.com/u>")
    with pytest.raises(ValueError, match="must use https://"):
        MessageBuilder().set_list_unsubscribe("http://example.com/u")
    with pytest.raises(ValueError, match="must use https://"):
        MessageBuilder().set_list_unsubscribe("https:///path")

    for bad_tpl in (True, 0, -3):
        with pytest.raises(ValueError, match="strictly positive integer"):
            MessageBuilder().set_template(bad_tpl)
    with pytest.raises(TypeError, match="language_active must be a bool"):
        MessageBuilder().set_template(10, language_active=cast("Any", "yes"))

    with pytest.raises(TypeError, match="must be str, got None"):
        MessageBuilder().set_headers(cast("Any", {"X-Null": None}))

    img = tmp_path / "cid.png"
    img.write_bytes(b"PNG")
    with pytest.raises(ValueError, match="Invalid Content-ID"):
        MessageBuilder().attach_inline(img, base_dir=tmp_path, content_id="bad cid!")

    # SendPayloadBuilder limits
    with pytest.raises(ValueError, match="At least one message is required"):
        SendPayloadBuilder().build()

    base_msg = (
        MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(text="hi").build()
    )
    spb = SendPayloadBuilder()
    for _ in range(SendPayloadBuilder.MAX_MESSAGES):
        spb.add_message(base_msg)
    with pytest.raises(ValueError, match="at most 50 messages"):
        spb.add_message(base_msg)

    # Defensive >MAX_MESSAGES check inside build()
    spb._messages.append(base_msg)
    with pytest.raises(ValueError, match="at most 50 messages"):
        spb.build()

    # Large batch passing upper-bound estimate check but under 15MB succeeds, >15MB fails
    medium_msg = (
        MessageBuilder()
        .set_sender("s@example.com")
        .add_recipient("r@example.com")
        .set_content(text="x" * (3 * 1024 * 1024))
        .build()
    )
    under_limit = SendPayloadBuilder().add_message(medium_msg).build()
    assert len(under_limit["Messages"]) == 1

    four_mb_msg = (
        MessageBuilder()
        .set_sender("s@example.com")
        .add_recipient("r@example.com")
        .set_content(text="y" * (4 * 1024 * 1024))
        .build()
    )
    over_batch = SendPayloadBuilder()
    for _ in range(4):
        over_batch.add_message(four_mb_msg)
    with pytest.raises(ValueError, match="exceeds 15MB limit"):
        over_batch.build()


def test_chunked_streamer_and_filesystem_security_real_files(
    local_tls_server: dict[str, Any], tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise ChunkedStreamer, zero-trust filesystem path validation, and multipart upload security."""
    # ChunkedStreamer invalid bounds
    for bad_cs in (True, 0, -1, 1.5):
        with pytest.raises(ValueError, match="chunk_size"):
            ChunkedStreamer.encode_file(tmp_path / "x", chunk_size=cast("Any", bad_cs))
    for bad_mb in (False, 0, -5, "10"):
        with pytest.raises(ValueError, match="max_bytes"):
            ChunkedStreamer.encode_file(tmp_path / "x", max_bytes=cast("Any", bad_mb))

    # Empty file + unaligned multi-chunk streaming
    empty_file = tmp_path / "empty.bin"
    empty_file.write_bytes(b"")
    assert ChunkedStreamer.encode_file(empty_file, chunk_size=4, safe_base_dir=tmp_path) == ""

    data_file = tmp_path / "chunked.bin"
    raw_bytes = bytes(range(25))
    data_file.write_bytes(raw_bytes)
    assert ChunkedStreamer.encode_file(data_file, chunk_size=7, safe_base_dir=tmp_path) == base64.b64encode(
        raw_bytes
    ).decode("ascii")

    # Exceed max_bytes at fstat (exercises finally: if fd_owned: os.close(fd))
    with pytest.raises(ValueError, match="exceeds safe threshold"):
        ChunkedStreamer.encode_file(data_file, safe_base_dir=tmp_path, max_bytes=10)

    # Non-regular fd via cross-platform os.pipe()
    r_fd, w_fd = os.pipe()
    try:
        with pytest.raises(ValueError, match="not a regular file"):
            ChunkedStreamer._assert_regular_bounded_fd(r_fd, data_file, 1024)
    finally:
        os.close(r_fd)
        os.close(w_fd)

    # Streaming read overflow
    with pytest.raises(ValueError, match="exceeds safe threshold"):
        ChunkedStreamer._read_stream_base64_chunks(io.BytesIO(b"0123456789"), "stream.bin", 3, 5)

    # O_NOFOLLOW ELOOP & generic OSError propagation in encode_file
    symlink_path = tmp_path / "sym_target.txt"
    try:
        symlink_path.symlink_to(data_file)
        has_real_symlink = True
    except (OSError, NotImplementedError):
        has_real_symlink = False

    if has_real_symlink:
        with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
            filesystem_security.validate_attachment_path(symlink_path, safe_base_dir=tmp_path)

        monkeypatch.setattr(
            SecurityGuard, "validate_attachment_path", staticmethod(lambda _p, safe_base_dir=None: symlink_path)
        )
        if hasattr(os, "O_NOFOLLOW"):
            with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
                ChunkedStreamer.encode_file(symlink_path, safe_base_dir=tmp_path)
        monkeypatch.undo()
    else:
        monkeypatch.setattr(Path, "is_symlink", lambda _self: True)
        with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
            filesystem_security.validate_attachment_path(data_file, safe_base_dir=tmp_path)
        monkeypatch.undo()

    # Simulate OSError(ELOOP) & non-ELOOP OSError in ChunkedStreamer.encode_file
    def _raise_eloop(*_args: Any, **_kwargs: Any) -> int:
        raise OSError(errno.ELOOP, "Too many levels of symbolic links")

    def _raise_eperm(*_args: Any, **_kwargs: Any) -> int:
        raise OSError(errno.EPERM, "Operation not permitted")

    monkeypatch.setattr(os, "open", _raise_eloop)
    with pytest.raises(ValueError, match="Symlinks are strictly forbidden"):
        ChunkedStreamer.encode_file(data_file, safe_base_dir=tmp_path)
    monkeypatch.setattr(os, "open", _raise_eperm)
    with pytest.raises(OSError, match="Operation not permitted"):
        ChunkedStreamer.encode_file(data_file, safe_base_dir=tmp_path)
    monkeypatch.undo()

    # _coerce_attachment_raw_path: str, Path, bytes PathLike, NUL in str & bytes
    assert filesystem_security._coerce_attachment_raw_path(_BytesPathLike(os.fsencode(data_file)))[1] == data_file
    with pytest.raises(ValueError, match="Null byte"):
        filesystem_security.validate_attachment_path("bad\x00file.txt")
    with pytest.raises(ValueError, match="Null byte"):
        filesystem_security.validate_attachment_path(cast("Any", _BytesPathLike(b"bad\x00file.txt")))

    # _validate_zero_trust_path: traversal, temp-dir allowed, forbidden roots, forbidden component, clean non-temp
    with pytest.raises(ValueError, match="Path traversal"):
        filesystem_security.validate_attachment_path(str(tmp_path / ".." / data_file.name))

    # Inside temp dir passes zero-trust without safe_base_dir
    assert filesystem_security.validate_attachment_path(data_file) == data_file.resolve()

    # Forbidden component cross-platform (/dev/null resolves with 'dev' part on Linux/macOS/Windows)
    with pytest.raises(ValueError, match="sensitive OS system directories"):
        filesystem_security.validate_attachment_path("/dev/null")

    # Forbidden root cross-platform (/boot on POSIX, C:\Windows on Windows) + direct unit check
    with pytest.raises(ValueError, match="sensitive OS system directories"):
        filesystem_security._validate_zero_trust_path("/boot/vmlinuz", Path("/boot/vmlinuz"))
    with pytest.raises(ValueError, match="sensitive OS system directories"):
        filesystem_security._validate_zero_trust_path(
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            Path("C:\\Windows\\System32\\drivers\\etc\\hosts"),
        )
    if os.name != "nt":
        with pytest.raises(ValueError, match="sensitive OS system directories"):
            filesystem_security.validate_attachment_path("/boot/nonexistent_kernel")
    filesystem_security._validate_zero_trust_path(
        "/safe_workspace/docs/report.txt", Path("/safe_workspace/docs/report.txt")
    )

    # safe_base_dir escape, missing file, directory, OSError on resolve() & exists()
    sub_dir = tmp_path / "sub"
    sub_dir.mkdir()
    with pytest.raises(ValueError, match="Traversal detected"):
        filesystem_security.validate_attachment_path(data_file, safe_base_dir=sub_dir)
    with pytest.raises(FileNotFoundError, match="not found"):
        filesystem_security.validate_attachment_path(tmp_path / "missing.txt", safe_base_dir=tmp_path)
    with pytest.raises(FileNotFoundError, match="not a file"):
        filesystem_security.validate_attachment_path(sub_dir, safe_base_dir=tmp_path)

    monkeypatch.setattr(Path, "resolve", lambda _self: (_ for _ in ()).throw(RuntimeError("symlink loop")))
    with pytest.raises(ValueError, match="Invalid attachment path"):
        filesystem_security.validate_attachment_path(data_file, safe_base_dir=tmp_path)
    monkeypatch.undo()

    monkeypatch.setattr(Path, "exists", lambda _self: (_ for _ in ()).throw(PermissionError("denied")))
    with pytest.raises(ValueError, match="Cannot inspect attachment path"):
        filesystem_security.validate_attachment_path(data_file, safe_base_dir=tmp_path)
    monkeypatch.undo()

    # check_file_size
    filesystem_security.check_file_size(data_file, max_size_bytes=1024)
    with pytest.raises(ValueError, match="not a regular file"):
        filesystem_security.check_file_size(sub_dir)
    with pytest.raises(ValueError, match="exceeds safe threshold"):
        filesystem_security.check_file_size(data_file, max_size_bytes=5)

    # validate_multipart_files: dict, list, passthroughs, 1..4-tuples, bytes & str & non-text, CRLF/NUL
    sanitizer = SecurityGuard.sanitize_headers
    filesystem_security.validate_multipart_files(None, header_sanitizer=sanitizer)
    filesystem_security.validate_multipart_files("not-a-container", header_sanitizer=sanitizer)
    filesystem_security.validate_multipart_files(
        [
            "bad-entry",
            ("a", "b", "c"),
            ("raw_io", io.BytesIO(b"x")),
            (123, (None,)),
            ("one", ("safe.txt",)),
            ("two", (b"safe.bin", io.BytesIO(b"abc"))),
            ("three", ("safe.txt", io.BytesIO(b"abc"), None)),
            ("four_non_map", ("safe.txt", io.BytesIO(b"abc"), "text/plain", "not-a-mapping")),
            ("four_map", ("safe.txt", io.BytesIO(b"abc"), "text/plain", {"X-Meta": "ok"})),
        ],
        header_sanitizer=sanitizer,
    )
    filesystem_security.validate_multipart_files(
        {"file": ("ok.png", io.BytesIO(b"png"), "image/png")},
        header_sanitizer=sanitizer,
    )

    for bad_files in (
        {"bad\r\nfield": ("ok.txt", io.BytesIO(b"x"))},
        [(b"bad\x00field", ("ok.txt", io.BytesIO(b"x")))],
        {"file": ("bad\nname.txt", io.BytesIO(b"x"))},
        {"file": ("ok.txt", io.BytesIO(b"x"), "text/plain\r\n")},
        {"file": ("ok.txt", io.BytesIO(b"x"), "text/plain", {"X-Bad": "val\r\n"})},
    ):
        with pytest.raises(ValueError):
            filesystem_security.validate_multipart_files(bad_files, header_sanitizer=sanitizer)

    # Real loopback TLS multipart upload + pre-flight rejection of CRLF filename
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]
    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        up = client.data_images.create(
            headers={"Content-Type": None},
            files=[("file", ("logo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png", {"X-Tag": "ok"}))],
        )
        assert up.status_code == 201
        with pytest.raises(ValueError, match="CRLF or NUL"):
            client.data_images.create(files={"file": ("evil\r\n.png", io.BytesIO(b"x"), "image/png")})


def test_html_guard_xss_dos_and_lazy_meta() -> None:
    """Exercise LazyHtmlGuardMeta, build_spam_guard_parser, XSS_PATTERN, parser handlers, and DoS limits."""

    class _FreshLazyGuard(metaclass=html_guard.LazyHtmlGuardMeta):
        pass

    parser_cls = _FreshLazyGuard._SpamGuardParser
    assert issubclass(parser_cls, object)
    with pytest.raises(AttributeError, match="has no attribute 'NO_SUCH_ATTR'"):
        _ = _FreshLazyGuard.NO_SUCH_ATTR

    # Direct parser inspection for executable tags blocked before parser by XSS_PATTERN
    direct_parser = html_guard.build_spam_guard_parser()()
    direct_parser.feed('<iframe src="https://evil.example"></iframe><p onclick="x()">hi</p><!-- c --><br/>')
    direct_parser.close()
    assert direct_parser.has_script is True
    assert direct_parser.is_safe is False
    assert any("Blocked executable tag: <iframe>" in issue for issue in direct_parser.issues)
    assert any("Blocked event handler: onclick" in issue for issue in direct_parser.issues)

    # Empty / whitespace fast-path
    assert html_guard.analyze_html_safety("", parser_factory=parser_cls) == {"is_safe": True, "issues": []}
    assert html_guard.analyze_html_safety("   \n\t ", parser_factory=parser_cls) == {"is_safe": True, "issues": []}

    # Max HTML size overflow
    with pytest.raises(ValueError, match="maximum safe length"):
        html_guard.analyze_html_safety("<p>123456</p>", parser_factory=parser_cls, max_html_size=5)

    # XSS_PATTERN rejections
    for xss_vec in (
        "<script>alert(1)</script>",
        '<svg onload="x()">',
        '<a href="javascript:alert(1)">x</a>',
        '<body onload="x()">',
    ):
        with pytest.raises(ValueError, match="Javascript/XSS"):
            html_guard.analyze_html_safety(xss_vec, parser_factory=parser_cls)

    # Parser-level event handler not matched by XSS_PATTERN
    with pytest.raises(ValueError, match="blocked script/event execution"):
        html_guard.analyze_html_safety('<img src="x" onmouseover="alert(1)"/>', parser_factory=parser_cls)

    # Tag-bomb DoS limit
    with pytest.raises(ValidationError, match="maximum tag limit"):
        html_guard.analyze_html_safety("<p>1</p><p>2</p><p>3</p>", parser_factory=parser_cls, max_tag_count=4)

    # Parser without max_tags + unexpected parser error wrapped into ValidationError
    class _FailingParser:
        has_script = False
        is_safe = True
        issues: list[str] = []

        def feed(self, _data: str) -> None:
            raise RuntimeError("parser crash")

        def close(self) -> None:
            return None

    with pytest.raises(ValidationError, match="Fatal HTML parsing error"):
        html_guard.analyze_html_safety("<p>ok</p>", parser_factory=_FailingParser)

    # Clean HTML exercising starttag, startendtag, endtag, comment
    safe_res = html_guard.analyze_html_safety(
        "<div><p>Safe <!-- comment --> <br/></p></div>",
        parser_factory=parser_cls,
    )
    assert safe_res == {"is_safe": True, "issues": []}


def test_guardrails_ssrf_idna_fingerprinting_timeouts_headers_segments_and_auth(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify SSRF, IDNA, fingerprinting, proxies, headers, timeouts, segments, and auth guardrails."""
    SecurityGuard.enable_audit_logging()
    assert SecurityGuard.resolve_tls_verify(True) is True
    assert SecurityGuard.filter_safe_kwargs({"verify": True, "proxies": None, "evil": 1}) == {
        "verify": True,
        "proxies": None,
    }

    # SSRF URL checks
    for valid_url in (
        "https://api.mailjet.com",
        "https://mailjet.com/",
        "https://eu.mailjet.com/",
        "https://localhost:8443/",
        "https://127.0.0.1:8443/",
        "https://[::1]:8443/",
    ):
        SecurityGuard.validate_config_url(valid_url)

    imds_host = str(ipaddress.IPv4Address((169 << 24) | (254 << 16) | (169 << 8) | 254))
    for bad_url in (
        "",
        "   ",
        "https://api.mailjet.com/\x00",
        "https://api.mailjet.com/#frag",
        "ftp://api.mailjet.com/",
        "https://user:pass@api.mailjet.com/",  # pragma: allowlist secret
        "https://[fe80::1%25eth0]/",
        f"https://{imds_host}/latest/meta-data/",
        "https://10.0.0.1/",
        "https://192.168.1.1/",
        "https://evil.example:8443/",
        "https://mailjet.com.evil.example/",
        "https://api.mailjet.com/?q=1",
    ):
        with pytest.raises(ValueError):
            SecurityGuard.validate_config_url(bad_url)

    # validate_target_url fast-path + fallback
    SecurityGuard.validate_target_url(
        "https://localhost:8443/v3/REST/contact?Limit=1",
        base_api_url="https://localhost:8443",
    )
    with pytest.raises(ValueError, match="fragments"):
        SecurityGuard.validate_target_url(
            "https://localhost:8443/v3/REST/contact#frag",
            base_api_url="https://localhost:8443/",
        )
    with pytest.raises(ValueError, match="control characters"):
        SecurityGuard.validate_target_url(
            "https://localhost:8443/v3/\u00e9\x07",
            base_api_url="https://localhost:8443/",
        )
    with pytest.raises(ValueError, match="not permitted"):
        SecurityGuard.validate_target_url(
            f"https://{imds_host}/latest",
            base_api_url="https://localhost:8443/",
        )
    SecurityGuard.validate_target_url("https://api.mailjet.com/v3/REST/contact")

    # Proxies & check_request_security
    SecurityGuard.check_request_security({})
    SecurityGuard.check_request_security({"proxies": "https://proxy.local:8443"})
    SecurityGuard.check_request_security({"proxies": "proxy.local:8443"})
    SecurityGuard.check_request_security({"proxies": {"https": "socks5h://proxy.local:1080", "http": None}})
    with pytest.warns(UserWarning, match="Unencrypted HTTP proxy"):
        SecurityGuard.check_request_security({"proxies": "http://proxy.local:8080"})
    with pytest.warns(UserWarning, match="Unencrypted HTTP proxy"):
        SecurityGuard.check_request_security({"proxies": {"http": "http://proxy.local:8080"}})

    with pytest.raises(TypeError, match="Invalid 'proxies' type"):
        SecurityGuard.check_request_security({"proxies": 123})
    with pytest.raises(TypeError, match="Invalid proxy URL type"):
        SecurityGuard.check_request_security({"proxies": {"https": 123}})
    with pytest.raises(ValueError, match="control characters"):
        SecurityGuard.check_request_security({"proxies": "https://proxy\r\n:8443"})
    with pytest.raises(ValueError, match="unsupported proxy scheme"):
        SecurityGuard.check_request_security({"proxies": "ftp://proxy:21"})

    # Headers & control chars
    assert SecurityGuard.sanitize_headers({"X-Tab": "a\tb", "X-None": None}) == {"X-Tab": "a\tb", "X-None": None}
    with pytest.raises(TypeError, match="header name type"):
        SecurityGuard.sanitize_headers(cast("Any", {123: "v"}))
    with pytest.raises(TypeError, match="header value type"):
        SecurityGuard.sanitize_headers(cast("Any", {"X-Val": 123}))
    with pytest.raises(ValueError, match="CRLF injection"):
        SecurityGuard.sanitize_headers({"X-Bad": "val\r\n"})
    with pytest.raises(ValueError, match="CRLF injection"):
        SecurityGuard.sanitize_headers({"X-NEL": "val\x85"})

    SecurityGuard.check_control_characters("field", "clean text")
    SecurityGuard.check_control_characters("field", 123)
    with pytest.raises(ValueError, match="Unprintable control character"):
        SecurityGuard.check_control_characters("field", "bad\x07")

    # Payload fingerprinting: volatile stripping, SandboxMode sensitivity, collections, non-str key fallback, cycles, depth
    p1 = {
        "Messages": [{"From": {"Email": "a@b.com"}, "CustomID": "cid-1", "EventPayload": "ep-1"}],
        "Tags": ("a", "b"),
        "Flags": {1, 2},
        "SandboxMode": False,
    }
    p2 = {
        "Messages": [{"From": {"Email": "a@b.com"}, "CustomID": "cid-2", "EventPayload": "ep-2"}],
        "Tags": ("a", "b"),
        "Flags": {1, 2},
        "SandboxMode": False,
    }
    p3 = {**p1, "SandboxMode": True}
    assert SecurityGuard.generate_payload_fingerprint(p1) == SecurityGuard.generate_payload_fingerprint(p2)
    assert SecurityGuard.generate_payload_fingerprint(p1) != SecurityGuard.generate_payload_fingerprint(p3)

    # Non-str dict key triggers stdlib json.dumps fallback when orjson is installed
    assert len(SecurityGuard.generate_payload_fingerprint(cast("Any", {1: "one", 2: [True, 2.5]}))) == 64

    # Exercise both _orjson fast-path and TypeError fallback deterministically
    def _fake_orjson_dumps(obj: Any, **_kwargs: Any) -> bytes:
        if any(not isinstance(k, str) for k in obj):
            raise TypeError("Dict key must be str")
        return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    expected_fp = SecurityGuard.generate_payload_fingerprint(p1)
    monkeypatch.setattr(guardrails_mod, "_orjson", SimpleNamespace(OPT_SORT_KEYS=1, dumps=_fake_orjson_dumps))
    assert SecurityGuard.generate_payload_fingerprint(p1) == expected_fp
    assert len(SecurityGuard.generate_payload_fingerprint(cast("Any", {1: "one", 2: "two"}))) == 64
    monkeypatch.undo()

    cyc_dict: dict[str, Any] = {"name": "loop"}
    cyc_dict["self"] = cyc_dict
    cyc_list: list[Any] = []
    cyc_list.append(cyc_list)
    assert len(SecurityGuard.generate_payload_fingerprint({"d": cyc_dict, "l": cyc_list})) == 64

    deep: dict[str, Any] = {}
    cur = deep
    for _ in range(55):
        nxt: dict[str, Any] = {}
        cur["n"] = nxt
        cur = nxt
    with pytest.raises(ValueError, match="Payload hashing failed"):
        SecurityGuard.generate_payload_fingerprint(deep)

    # Timeouts
    assert SecurityGuard.validate_timeout(10) == 10.0
    assert SecurityGuard.validate_timeout((3, 7.5)) == (3.0, 7.5)
    with pytest.warns(DeprecationWarning, match="infinite socket blocking"):
        assert SecurityGuard.validate_timeout(None) is None
    for bad_type in (True, "10"):
        with pytest.raises(TypeError):
            SecurityGuard.validate_timeout(cast("Any", bad_type))
    for bad_val in (10**400, float("inf"), float("nan"), 0, -1, 86401, (5,)):
        with pytest.raises(ValueError):
            SecurityGuard.validate_timeout(cast("Any", bad_val))
    with pytest.warns(DeprecationWarning), pytest.raises(TypeError, match="valid numeric values"):
        SecurityGuard.validate_timeout(cast("Any", (5, None)))

    # IDNA domain normalization
    assert SecurityGuard.normalize_domain("") == ""
    assert SecurityGuard.normalize_domain("Api.Mailjet.COM") == "api.mailjet.com"
    assert SecurityGuard.normalize_domain("User@Example.COM") == "User@example.com"
    assert SecurityGuard.normalize_domain("user@bücher.example") == "user@xn--bcher-kva.example"
    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain("a" * 255)
    with pytest.raises(ValueError, match="Invalid IDN in email"):
        SecurityGuard.normalize_domain("u@" + ("b" * 64) + ".com")
    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain("bad..idn")
    with pytest.raises(ValueError, match="Invalid IDN in email"):
        SecurityGuard.normalize_domain("u@.badidn")

    # Segment sanitization
    assert SecurityGuard.sanitize_segment(None) == ""
    assert SecurityGuard.sanitize_segment("user.name") == "user%2Ename"
    for bad_seg_type in ({"a": 1}, [1], {1}, True):
        with pytest.raises(TypeError, match="Invalid segment type"):
            SecurityGuard.sanitize_segment(bad_seg_type)
    for bad_seg in ("%25252541", "a?b", "a%23b", "..", "a/b", "a\\b", "\x07", "{{x}}", "<script>"):
        with pytest.raises(ValueError):
            SecurityGuard.sanitize_segment(bad_seg)

    # Log trace sanitization
    assert SecurityGuard.sanitize_log_trace("") == ""
    assert SecurityGuard.sanitize_log_trace("cid 1\r\n\x00") == "cid_1___"

    # Auth validation
    assert SecurityGuard.validate_and_coerce_auth(None) is None
    assert SecurityGuard.validate_and_coerce_auth("  tok_123  ") == "tok_123"
    coerced = SecurityGuard.validate_and_coerce_auth((" pub ", " priv "))
    assert isinstance(coerced, SecretAuth)

    for bad_tok in ("   ", "tok\r\nmore", "tok space", "tok\u00a0nb", "tok\u200bzw"):
        with pytest.raises(ValueError):
            SecurityGuard.validate_and_coerce_auth(bad_tok)
    for bad_pair in (("onlyone",), (" ", "sec"), ("key\n", "sec"), ("key\u00a0x", "sec"), ("key\u200bx", "sec")):
        with pytest.raises(ValueError):
            SecurityGuard.validate_and_coerce_auth(cast("Any", bad_pair))
    with pytest.raises(TypeError, match="must be strings"):
        SecurityGuard.validate_and_coerce_auth(cast("Any", (123, "sec")))
    with pytest.raises(TypeError, match="Invalid auth type"):
        SecurityGuard.validate_and_coerce_auth(cast("Any", 123))


def test_telemetry_and_redacting_filter_integration(
    local_tls_server: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Exercise telemetry extraction/logging and RedactingFilter across real loopback Client calls and edge structures."""
    # extract_telemetry variants
    assert telemetry.extract_telemetry(None) == ("", {})
    assert telemetry.extract_telemetry("plain") == ("", {})
    assert telemetry.extract_telemetry(["not-a-mapping"]) == ("", {})
    assert telemetry.extract_telemetry(_BrokenMapping()) == ("", {})

    trace_s, trace_d = telemetry.extract_telemetry({"Messages": [{"CustomID": "cid 1\n", "TemplateID": 99}]})
    assert trace_s == " | Trace: [CustomID=cid_1_ TemplateID=99]" or trace_s == (
        " | Trace: [TemplateID=99 CustomID=cid_1_]"
    )
    assert trace_d == {"mailjet.customid": "cid_1_", "mailjet.templateid": "99"}

    flat_s, flat_d = telemetry.extract_telemetry({"CustomID": "top-cid"})
    assert flat_s == " | Trace: [CustomID=top-cid]"
    assert flat_d == {"mailjet.customid": "top-cid"}

    empty_msgs_s, empty_msgs_d = telemetry.extract_telemetry({"Messages": [], "TemplateID": 12})
    assert empty_msgs_s == " | Trace: [TemplateID=12]"
    assert empty_msgs_d == {"mailjet.templateid": "12"}

    list_s, list_d = telemetry.extract_telemetry([{"CustomID": "list-cid"}])
    assert list_s == " | Trace: [CustomID=list-cid]"
    assert list_d == {"mailjet.customid": "list-cid"}

    # Direct logger with RedactingFilter attached
    test_logger = logging.getLogger("mailjet_rest.test.redaction")
    test_logger.handlers.clear()
    test_logger.filters.clear()
    test_logger.propagate = False
    test_logger.setLevel(logging.DEBUG)
    test_logger.addFilter(RedactingFilter())
    capture = _ListHandler()
    test_logger.addHandler(capture)

    # log_api_response + record_debug_telemetry branches
    err_resp = SimpleNamespace(status_code=500, text="Bad\r\n" + ("x" * 30))
    ok_resp = SimpleNamespace(status_code=201, text="")
    none_resp = SimpleNamespace(status_code=None, text="")

    telemetry.log_api_response(test_logger, "POST", "https://localhost/v3/send", err_resp, trace_s, max_chars=10)
    telemetry.log_api_response(test_logger, "GET", "https://localhost/v3/contact", none_resp, "")
    telemetry.record_debug_telemetry(
        test_logger, "POST", "https://localhost/v3/send", ok_resp, {"CustomID": "ok"}, None
    )
    telemetry.record_debug_telemetry(
        test_logger, "POST", "https://localhost/v3/send", err_resp, {"CustomID": "no"}, None
    )
    test_logger.setLevel(logging.INFO)
    telemetry.record_debug_telemetry(
        test_logger, "POST", "https://localhost/v3/send", ok_resp, {"CustomID": "skip"}, None
    )
    test_logger.setLevel(logging.DEBUG)

    # RedactingFilter deep coverage: msg, tuple args, dict args, NamedTuple, model_dump, __dict__, slots, broken __str__, sets, depth, exc, extras
    test_logger.info("Plain harmless message")
    test_logger.info("Authorization: Basic dXNlcjpwYXNz token=tok_inline")
    test_logger.info("Tuple args %s %s", "Authorization: Bearer tok_tuple", _SecretPair("t1", "ok"))
    test_logger.info(
        "Dict args %(auth)s %(deep)s",
        {
            "authorization": "Basic abc",
            "auth": "clean",
            "deep": {
                "a": {"b": {"c": {"d": {"e": "too_deep"}}}},
                "lst": [1, 2.5, True, None, _ModelDumpObj(), _DictObj()],
                "set_v": {"Authorization: Bearer s1"},
                "fset_v": frozenset({"api_key=s2"}),
                "slots_ok": _SlotsObj("token=slot_secret"),
                "slots_bad": _BrokenStrSlotsObj(),
            },
        },
    )
    test_logger.info(
        "Extras test",
        extra={"api_key": "secret_extra", "note": "Authorization: Bearer extra_tok"},  # pragma: allowlist secret
    )

    try:
        raise ValueError("Authorization: Bearer exc_secret_tok")
    except ValueError as exc:
        rec_info = test_logger.makeRecord(
            test_logger.name,
            logging.ERROR,
            __file__,
            1,
            "Failure info",
            (),
            (type(exc), exc, exc.__traceback__),
        )
        test_logger.handle(rec_info)

    rec_text = test_logger.makeRecord(test_logger.name, logging.ERROR, __file__, 1, "Failure text", (), None)
    rec_text.exc_text = "cached Authorization: Bearer exc_text_tok"
    test_logger.handle(rec_text)

    assert RedactingFilter._redact_str(cast("Any", 123)) == "[REDACTION_FAILED_UNSAFE_STRING]"

    # Filter exception failsafe must return True without crashing caller
    rf = RedactingFilter()
    monkeypatch.setattr(rf, "_scrub_record", lambda _r: (_ for _ in ()).throw(RuntimeError("filter fail")))
    safe_rec = test_logger.makeRecord(test_logger.name, logging.INFO, __file__, 1, "msg", (), None)
    assert rf.filter(safe_rec) is True
    monkeypatch.undo()

    all_text = "\n".join(
        f"{r.getMessage()} {r.exc_text or ''} {getattr(r, 'api_key', '')} {getattr(r, 'note', '')}"
        for r in capture.records
    )
    assert "API Error 500" in all_text
    assert "API Success 200" in all_text
    assert "API Success 201" in all_text
    for leaked in (
        "dXNlcjpwYXNz",
        "tok_inline",
        "tok_tuple",
        "tok_from_model",
        "secret-key-val",
        "my_secret_val",
        "slot_secret",
        "secret_extra",
        "extra_tok",
        "exc_secret_tok",
        "exc_text_tok",
    ):
        assert leaked not in all_text

    # Real sync Client loopback TLS telemetry verification
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]
    client_logger = logging.getLogger("mailjet_rest.client")
    old_level = client_logger.level
    sync_capture = _ListHandler()
    client_logger.addHandler(sync_capture)
    client_logger.setLevel(logging.DEBUG)
    try:
        with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
            msg = (
                MessageBuilder()
                .set_sender("sync@example.com")
                .add_recipient("to@example.com")
                .set_custom_id("sync-trace-9")
                .set_template(321)
                .build()
            )
            resp = client.send_v31.create(data=SendPayloadBuilder().add_message(msg).build())
            assert resp.status_code == 200
    finally:
        client_logger.removeHandler(sync_capture)
        client_logger.setLevel(old_level)

    assert any(
        "CustomID=sync-trace-9" in r.getMessage() and "TemplateID=321" in r.getMessage() for r in sync_capture.records
    )
