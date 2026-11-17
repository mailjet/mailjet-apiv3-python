"""Targeted Wave 5 unit tests hardening mutation coverage across builders, endpoints, and transport security."""

from __future__ import annotations

import base64
import errno
import os
import socket
import ssl
import stat
import sys
import warnings
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
import requests

from mailjet_rest.builders import (
    ChunkedStreamer,
    MessageBuilder,
    SendPayloadBuilder,
    TemplateContentBuilder,
)
from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.types import SendV31Message
from mailjet_rest.utils.transport_security import (
    _KEEPALIVE_OPTION,
    _KEEPALIVE_SOCKET_OPTIONS,
    SecretAuth,
    SecureHTTPAdapter,
    _build_tls_context,
    get_secure_ssl_context,
    resolve_tls_verify,
)


class _BytesPath:
    """PathLike returning bytes from __fspath__ to exercise TypeError paths."""

    def __fspath__(self) -> bytes:
        return b"/tmp/ca.pem"


def test_transport_security_verify_audit_and_errors(tmp_path: Path) -> None:
    """Verify resolve_tls_verify audit hooks, error messages, and boundary types."""
    audit_events: list[tuple[str, tuple[object, ...]]] = []

    def hook(event: str, args: tuple[object, ...]) -> None:
        if event == "mailjet.security.tls_disabled":
            audit_events.append((event, args))

    sys.addaudithook(hook)

    for bad_verify in (False, None):
        with pytest.raises(ValueError) as exc_info:
            resolve_tls_verify(bad_verify)
        assert (
            str(exc_info.value)
            == "Security Violation: Mailjet API TLS verification cannot be disabled (verify=False is forbidden)."
        )

    assert ("mailjet.security.tls_disabled", ("False",)) in audit_events
    assert ("mailjet.security.tls_disabled", ("None",)) in audit_events
    assert resolve_tls_verify(verify=True) is True

    with pytest.raises(TypeError) as bytes_exc:
        resolve_tls_verify(_BytesPath())  # type: ignore[arg-type]
    assert str(bytes_exc.value) == "Invalid CA bundle path type: expected str or os.PathLike[str], got bytes."

    for empty_or_ctrl in ("", "   ", f"{tmp_path}/bad\n.pem", f"{tmp_path}/bad\x00.pem"):
        with pytest.raises(ValueError) as val_exc:
            resolve_tls_verify(empty_or_ctrl)
        assert str(val_exc.value) == "Invalid CA bundle path: must be a non-empty path without control characters."

    missing = tmp_path / "missing.pem"
    with pytest.raises(ValueError) as missing_exc:
        resolve_tls_verify(str(missing))
    assert str(missing_exc.value) == f"Custom CA bundle path does not exist or is not a file: {missing}"

    with pytest.raises(ValueError) as dir_exc:
        resolve_tls_verify(tmp_path)
    assert str(dir_exc.value) == f"Custom CA bundle path does not exist or is not a file: {tmp_path}"

    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy", encoding="utf-8")
    assert resolve_tls_verify(ca_file) == str(ca_file)

    with pytest.raises(TypeError) as int_exc:
        resolve_tls_verify(123)
    assert str(int_exc.value) == "Invalid 'verify' type: expected bool, str, or PathLike, got int."


def test_ssl_context_cache_invalidation_adapter_and_secret_auth(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SSLContext caching by mtime/size, adapter cert_verify isolation, and SecretAuth equality/hashing."""
    ctx_default_1 = get_secure_ssl_context()
    ctx_default_2 = _build_tls_context(None)
    assert ctx_default_1 is ctx_default_2
    assert ctx_default_1.minimum_version == ssl.TLSVersion.TLSv1_2
    assert ctx_default_1.check_hostname is True
    assert ctx_default_1.verify_mode == ssl.CERT_REQUIRED
    assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) == _KEEPALIVE_OPTION
    assert _KEEPALIVE_OPTION in _KEEPALIVE_SOCKET_OPTIONS

    # Generate valid self-signed CA cert via cryptography or mock load_verify_locations/create_default_context
    ca_one = tmp_path / "ca1.pem"
    ca_two = tmp_path / "ca2.pem"
    ca_one.write_text("pem-a", encoding="utf-8")
    ca_two.write_text("pem-b", encoding="utf-8")

    fake_created: list[tuple[str | None, MagicMock]] = []

    def fake_create_default_context(*, cafile: str | None = None) -> MagicMock:
        ctx = MagicMock(spec=ssl.SSLContext)
        ctx.options = 0
        ctx.cafile_seen = cafile
        fake_created.append((cafile, ctx))
        return ctx

    monkeypatch.setattr("mailjet_rest.utils.transport_security.ssl.create_default_context", fake_create_default_context)
    # Clear lru_cache so mocked context creation executes deterministically
    from mailjet_rest.utils.transport_security import _cached_ssl_context

    _cached_ssl_context.cache_clear()
    try:
        first = get_secure_ssl_context(str(ca_one))
        second = get_secure_ssl_context(str(ca_one))
        assert first is second
        assert getattr(first, "cafile_seen") == str(ca_one)

        # Updating size + mtime invalidates cache and yields a fresh context
        ca_one.write_text("pem-a-updated-length", encoding="utf-8")
        st_now = ca_one.stat()
        os.utime(ca_one, ns=(st_now.st_atime_ns, st_now.st_mtime_ns + 1_000_000))
        third = get_secure_ssl_context(str(ca_one))
        assert third is not first

        adapter = SecureHTTPAdapter(ca_bundle=str(ca_one))
        assert adapter._ca_bundle == str(ca_one)
        assert SecureHTTPAdapter._get_secure_ssl_context(str(ca_two)) is get_secure_ssl_context(str(ca_two))

        conn = SimpleNamespace(
            ssl_context=None, ca_certs="stale", ca_cert_dir="stale_dir", assert_hostname=None, cert_reqs=None
        )
        adapter.cert_verify(conn, "HTTPS://api.example.com", verify=True, cert=None)
        assert conn.ssl_context is not adapter._ssl_context
        assert conn.ca_certs is None
        assert conn.ca_cert_dir is None

        conn_same = SimpleNamespace(
            ssl_context=None, ca_certs="stale", ca_cert_dir="stale_dir", assert_hostname=None, cert_reqs=None
        )
        adapter.cert_verify(conn_same, "https://api.example.com", verify=str(ca_one), cert=None)
        assert conn_same.ssl_context is adapter._ssl_context
        assert conn_same.ca_certs is None
        assert conn_same.ca_cert_dir is None
    finally:
        _cached_ssl_context.cache_clear()

    auth_a1 = SecretAuth(("key1", "sec1"))
    auth_a2 = SecretAuth(("key1", "sec1"))
    auth_diff_key = SecretAuth(("key2", "sec1"))
    auth_diff_sec = SecretAuth(("key1", "sec2"))

    req = requests.Request("GET", "https://api.example.com").prepare()
    out_req = auth_a1(req)
    assert out_req is req
    expected_hdr = "Basic " + base64.b64encode(b"key1:sec1").decode("ascii")
    assert out_req.headers["Authorization"] == expected_hdr

    assert auth_a1 == auth_a2
    assert hash(auth_a1) == hash(auth_a2)
    assert auth_a1 != auth_diff_key
    assert auth_a1 != auth_diff_sec
    assert auth_a1 == ("key1", "sec1")
    assert auth_a1 != ("key1", "other")
    assert auth_a1 != "not-an-auth"

    with pytest.raises(TypeError) as idx_exc:
        _ = auth_a1[0]
    assert str(idx_exc.value) == "Credential extraction via indexing is blocked for security (CWE-316)."

    with pytest.raises(TypeError) as iter_exc:
        list(auth_a1)
    assert str(iter_exc.value) == "Credential extraction via iteration is blocked for security (CWE-316)."


def test_chunked_streamer_boundaries_and_errors(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Exercise ChunkedStreamer.encode_file validation, chunk sizing, O_NOFOLLOW, and fstat guards."""
    sample = tmp_path / "payload.bin"
    raw_bytes = b"abcdefghij"  # 10 bytes
    sample.write_bytes(raw_bytes)

    for bad_chunk in (True, False, 0, -3, "3"):
        with pytest.raises(ValueError) as exc_info:
            ChunkedStreamer.encode_file(sample, chunk_size=bad_chunk, safe_base_dir=tmp_path)  # type: ignore[arg-type]
        assert str(exc_info.value) == "chunk_size must be a strictly positive integer."

    for bad_max in (True, False, 0, -1, "10"):
        with pytest.raises(ValueError) as exc_info:
            ChunkedStreamer.encode_file(sample, max_bytes=bad_max, safe_base_dir=tmp_path)  # type: ignore[arg-type]
        assert str(exc_info.value) == "max_bytes must be a strictly positive integer."

    # chunk_size=1 uses step=max(3, 0)=3 across multiple base64 chunks
    encoded_small = ChunkedStreamer.encode_file(sample, chunk_size=1, safe_base_dir=tmp_path, max_bytes=len(raw_bytes))
    assert encoded_small == base64.b64encode(raw_bytes).decode("ascii")

    # chunk_size=6 (two 6-byte / 4-byte reads) also matches standard base64
    assert ChunkedStreamer.encode_file(sample, chunk_size=6, safe_base_dir=tmp_path) == base64.b64encode(
        raw_bytes
    ).decode("ascii")

    with pytest.raises(ValueError) as cap_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path, max_bytes=len(raw_bytes) - 1)
    assert str(cap_exc.value) == "Security Violation: File 'payload.bin' exceeds safe threshold."

    # Simulate O_NOFOLLOW ELOOP on os.open directly
    def raise_eloop(*args: object, **kwargs: object) -> int:
        raise OSError(errno.ELOOP, "Too many symbolic links encountered")

    monkeypatch.setattr("mailjet_rest.builders.os.open", raise_eloop)
    with pytest.raises(ValueError) as sym_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    assert str(sym_exc.value) == "Security Violation (CWE-22): Symlinks are strictly forbidden for attachments."

    # Non-ELOOP OSError propagates directly
    def raise_eacces(*args: object, **kwargs: object) -> int:
        raise OSError(errno.EACCES, "Permission denied")

    monkeypatch.setattr("mailjet_rest.builders.os.open", raise_eacces)
    with pytest.raises(PermissionError):
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    monkeypatch.undo()

    # Non-regular fd reported by fstat raises ValueError and closes fd
    monkeypatch.setattr(
        "mailjet_rest.builders.os.fstat",
        lambda _fd: os.stat_result((stat.S_IFIFO | 0o600, 0, 0, 0, 0, 0, 0, 0, 0, 0)),
    )
    with pytest.raises(ValueError) as fifo_exc:
        ChunkedStreamer.encode_file(sample, safe_base_dir=tmp_path)
    assert "Path is not a regular file:" in str(fifo_exc.value)


def test_builders_complete_contracts_and_boundaries(tmp_path: Path) -> None:
    """Verify validation messages, defaults, RFC 8058 flags, CID stripping, 102KB boundary, and deepcopy."""
    mb = MessageBuilder()
    with pytest.raises(TypeError) as type_exc:
        mb.set_sender(123)  # type: ignore[arg-type]
    assert str(type_exc.value) == "Invalid type for sender: expected str, got int"

    with pytest.raises(ValueError, match="CWE-93"):
        mb.set_sender("bad\r\n@example.com")

    for bad_email in ("no-at-sign", "bad space@example.com", "@example.com", "user@"):
        with pytest.raises(ValueError) as email_exc:
            mb.set_sender(bad_email)
        assert str(email_exc.value) == f"Invalid email address for sender: {bad_email!r}"

    with pytest.raises(TypeError) as hdr_none_exc:
        mb.set_headers({"X-Null": None})  # type: ignore[dict-item]
    assert str(hdr_none_exc.value) == "Header 'X-Null' value must be str, got None"

    with pytest.raises(ValueError, match="header 'X-Test'"):
        mb.set_headers({"X-Test": "val\r\ninject"})

    # Subject, EventPayload, Template, Tracking, List-Unsubscribe errors and outputs
    with pytest.raises(ValueError, match="subject"):
        mb.set_subject("Hi\r\nX-Inject: 1")
    with pytest.raises(ValueError, match="EventPayload"):
        mb.set_event_payload("ok\nevil")
    with pytest.raises(ValueError, match="CustomID"):
        mb.set_custom_id("id\x00bad")
    with pytest.raises(ValueError, match="TrackClicks"):
        mb.set_tracking(clicks="invalid")  # type: ignore[arg-type]

    mb.set_sender("sender@example.com", "Sender")
    mb.add_recipient("to1@example.com", "To One")
    mb.add_recipient("to2@example.com")
    mb.add_cc("cc1@example.com", "CC One")
    mb.add_cc("cc2@example.com")
    mb.add_bcc("bcc1@example.com", "BCC One")
    mb.add_bcc("bcc2@example.com")
    mb.set_reply_to("reply@example.com", "Reply")
    mb.set_subject("Order Update")
    mb.set_event_payload('{"id":1}')
    mb.set_template(98765, language_active=False)
    mb.set_headers({"X-Keep": "yes"})

    with pytest.raises(ValueError, match="unsubscribe_url"):
        mb.set_list_unsubscribe("https://example.com/u\r\nbad")
    for bracketed in ("<https://example.com/u>", "https://example.com/u>", "<https://example.com/u"):
        with pytest.raises(ValueError) as br_exc:
            mb.set_list_unsubscribe(bracketed)
        assert str(br_exc.value) == "Invalid RFC 8058 unsubscribe URL: angle brackets are forbidden."
    with pytest.raises(ValueError, match="https:// with a valid host"):
        mb.set_list_unsubscribe("https://")
    with pytest.raises(ValueError, match="mailto_address"):
        mb.set_list_unsubscribe("https://example.com/u", mailto_address="@bad.example.com")

    mb.set_list_unsubscribe("https://example.com/u", one_click=False)
    built_no_oneclick = mb.build()
    headers = built_no_oneclick.get("Headers")
    assert headers is not None
    assert headers["X-Keep"] == "yes"
    assert headers["List-Unsubscribe"] == "<https://example.com/u>"
    assert "List-Unsubscribe-Post" not in headers
    assert built_no_oneclick["Subject"] == "Order Update"
    assert built_no_oneclick.get("EventPayload") == '{"id":1}'
    assert built_no_oneclick.get("TemplateID") == 98765
    assert built_no_oneclick.get("TemplateLanguage") is False
    assert built_no_oneclick.get("ReplyTo") == {"Email": "reply@example.com", "Name": "Reply"}
    assert built_no_oneclick["To"] == [{"Email": "to1@example.com", "Name": "To One"}, {"Email": "to2@example.com"}]
    assert built_no_oneclick.get("Cc") == [{"Email": "cc1@example.com", "Name": "CC One"}, {"Email": "cc2@example.com"}]
    assert built_no_oneclick.get("Bcc") == [
        {"Email": "bcc1@example.com", "Name": "BCC One"},
        {"Email": "bcc2@example.com"},
    ]

    # Attachments, content_id stripping/errors, and base_dir confinement
    unknown_ext = tmp_path / "blob.unknownext999"
    unknown_ext.write_bytes(b"123")
    outside = tmp_path / "sub"
    outside.mkdir()
    mb_att = MessageBuilder().set_sender("s@example.com").add_recipient("r@example.com").set_content(text="ok")

    with pytest.raises(ValueError):
        mb_att.attach_file(unknown_ext, base_dir=outside)
    with pytest.raises(ValueError):
        mb_att.attach_inline(unknown_ext, base_dir=outside)

    mb_att.attach_file(unknown_ext, base_dir=tmp_path)
    mb_att.attach_inline(unknown_ext, base_dir=tmp_path, content_id=" <cid-99> ")
    for bad_cid in ("<open", "close>", "", "bad cid"):
        with pytest.raises(ValueError, match="Invalid Content-ID value"):
            mb_att.attach_inline(unknown_ext, base_dir=tmp_path, content_id=bad_cid)

    att_res = mb_att.build()
    attachments = att_res.get("Attachments")
    assert attachments is not None
    inlined = att_res.get("InlinedAttachments")
    assert inlined is not None
    assert attachments[0]["ContentType"] == "application/octet-stream"
    assert inlined[0]["ContentType"] == "application/octet-stream"
    assert inlined[0].get("ContentID") == "cid-99"

    # Exactly 102 * 1024 bytes emits zero warning; +1 byte warns with exact text
    boundary_msg = (
        MessageBuilder()
        .set_sender("s@example.com")
        .add_recipient("r@example.com")
        .attach_inline(unknown_ext, base_dir=tmp_path, content_id="hero")
        .set_content(html=("a" * (102 * 1024 - len('<img src="CID:hero">'))) + '<img src="CID:hero">')
    )
    with warnings.catch_warnings(record=True) as rec:
        warnings.simplefilter("always")
        boundary_msg.build()
    # Clean 102KB exact boundary with CID present should produce 0 clip warnings
    assert not any("102 KB" in str(w.message) for w in rec)

    over_msg = (
        MessageBuilder()
        .set_sender("s@example.com")
        .add_recipient("r@example.com")
        .set_content(html="a" * (102 * 1024 + 1))
    )
    with pytest.warns(UserWarning) as clip_warn:
        over_msg.build()
    assert str(clip_warn[0].message) == "Deliverability Warning: HTMLPart exceeds Gmail 102 KB clip threshold."

    # SendPayloadBuilder empty message text + deep copy on dict & globals + SandboxMode off/on
    empty_batch = SendPayloadBuilder()
    with pytest.raises(ValueError) as empty_exc:
        empty_batch.build()
    assert str(empty_exc.value) == "Payload validation failed: At least one message is required."

    raw_msg: SendV31Message = {
        "From": {"Email": "s@example.com"},
        "To": [{"Email": "r@example.com"}],
        "Subject": "Hi",
        "TextPart": "hi",
    }
    globs = {"Headers": {"X-G": "1"}}
    batch = SendPayloadBuilder().add_message(raw_msg).set_globals(globs).set_sandbox_mode(False)
    raw_msg["To"].append({"Email": "mutated@example.com"})
    globs["Headers"]["X-G"] = "mutated"
    batch_res = batch.build()
    batch_globals = batch_res.get("Globals")
    assert batch_globals is not None
    assert len(batch_res["Messages"][0]["To"]) == 1
    assert batch_globals["Headers"]["X-G"] == "1"
    assert "SandboxMode" not in batch_res

    # TemplateContentBuilder CRLF checks and deep meta errors
    tb = TemplateContentBuilder()
    with pytest.raises(ValueError, match="author"):
        tb.set_meta(author="a\nb")
    with pytest.raises(ValueError, match="name"):
        tb.set_meta(name="n\rb")
    with pytest.raises(ValueError, match="locale"):
        tb.set_meta(locale="en\x00US")


def test_endpoint_contracts_stream_errors_routing_and_cast(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify Endpoint CRUD forwarding, routing, _parse_stream_page errors, and _cast_query_param."""
    captured: list[dict[str, object]] = []

    def fake_api_call(
        self: Client,
        method: str,
        url: str,
        *,
        headers: object = None,
        data: object = None,
        filters: object = None,
        timeout: object = None,
        action_id: object = None,
        **kwargs: object,
    ) -> requests.Response:
        captured.append(
            {
                "method": method,
                "url": url,
                "headers": headers,
                "data": data,
                "filters": filters,
                "timeout": timeout,
                "action_id": action_id,
                "kwargs": kwargs,
            }
        )
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(Client, "api_call", fake_api_call)

    with Client(auth=("pub", "priv"), config=Config(api_url="https://api.mailjet.com/", version="v3")) as c:
        c.contact.create(
            id=11,
            action_id=22,
            data={"Email": "u@example.com"},
            headers={"X-C": "1"},
            filters={"Show": "all"},
            timeout=9.0,
        )
        assert len(captured) == 1
        assert captured[0]["method"] == "POST"
        assert captured[0]["url"] == "https://api.mailjet.com/v3/REST/contact/11/22"
        assert captured[0]["headers"] == {"Content-Type": "application/json", "X-C": "1"}
        assert captured[0]["filters"] == {"Show": "all"}
        assert captured[0]["timeout"] == 9.0

        c.contact.update(
            id=33,
            action_id=44,
            data={"Name": "Alice"},
            headers={"X-U": "2"},
            filters={"F": "1"},
            timeout=8.0,
        )
        assert len(captured) == 2
        assert captured[1]["method"] == "PUT"
        assert captured[1]["url"] == "https://api.mailjet.com/v3/REST/contact/33/44"
        assert captured[1]["headers"] == {"Content-Type": "application/json", "X-U": "2"}
        assert captured[1]["filters"] == {"F": "1"}
        assert captured[1]["timeout"] == 8.0

        c.contact.delete(id=55, action_id=66, timeout=7.0)
        assert len(captured) == 3
        assert captured[2]["method"] == "DELETE"
        assert captured[2]["url"] == "https://api.mailjet.com/v3/REST/contact/55/66"
        assert captured[2]["timeout"] == 7.0

        with pytest.warns(DeprecationWarning) as tpl_warn:
            tpl_url = c.templates._build_url()
        assert str(tpl_warn[0].message) == "Mailjet API Ambiguity: Email API (v3) uses singular '/template'"
        assert tpl_url == "https://api.mailjet.com/v3/REST/templates"

        assert c.send._build_url() == "https://api.mailjet.com/v3/send"
        assert (
            c.contactslist_csverror._build_url(id_val=77)
            == "https://api.mailjet.com/v3/DATA/contactslist/77/CSVError/text:csv"
        )
        assert c.contactslist_csvdata._build_headers()["Content-Type"] == "text/plain"

    # _parse_stream_page exact status_code/body slicing & AttributeError handling
    no_attr_resp = SimpleNamespace(json=MagicMock(side_effect=AttributeError("missing")), status_code=None, text=None)
    with pytest.raises(MailjetApiError) as err1:
        Endpoint._parse_stream_page(no_attr_resp)
    assert str(err1.value) == "Malformed JSON body returned during stream() pagination."
    assert err1.value.status_code == 0
    assert err1.value.response_body == ""

    long_resp = SimpleNamespace(status_code=504, text="x" * 700, json=lambda: [1, 2])
    with pytest.raises(MailjetApiError) as err2:
        Endpoint._parse_stream_page(long_resp)
    assert str(err2.value) == "Expected JSON object in stream() response."
    assert err2.value.status_code == 504
    assert len(err2.value.response_body or "") == 500

    empty_data_resp = SimpleNamespace(status_code=200, text="{}", json=dict)
    assert Endpoint._parse_stream_page(empty_data_resp) == []

    # _validate_stream_args exact messages + chunk_size=1 + max_items=1
    with Client(auth=("pub", "priv")) as c2:
        with pytest.raises(ValueError) as cs_exc:
            next(c2.contact.stream(chunk_size=0))
        assert str(cs_exc.value) == "stream() chunk_size must be a strictly positive integer."

        with pytest.raises(ValueError) as mi_exc:
            next(c2.contact.stream(max_items=-1))
        assert str(mi_exc.value) == "stream() max_items must be a non-negative integer or None."

        monkeypatch.setattr(
            Endpoint,
            "get",
            lambda _self, **_kw: SimpleNamespace(status_code=200, text="{}", json=lambda: {"Data": [{"ID": 9}]}),
        )
        assert list(c2.contact.stream(chunk_size=1, max_items=1)) == [{"ID": 9}]

    # _cast_query_param full truthiness, empty collection type, and bool numeric rejection
    assert Endpoint._cast_query_param(orig_ref=True, raw_values="T") is True
    assert Endpoint._cast_query_param(orig_ref=True, raw_values="false") is False
    empty_str = Endpoint._cast_query_param("s", [])
    assert empty_str == "" and isinstance(empty_str, str)
    with pytest.raises(TypeError) as bool_num_exc:
        Endpoint._cast_query_param(orig_ref=0, raw_values=True)
    assert str(bool_num_exc.value) == "Boolean value is not a valid numeric query parameter."
