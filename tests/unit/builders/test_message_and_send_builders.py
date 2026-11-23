# pyright: reportTypedDictNotRequiredAccess=false
"""Unit tests for MessageBuilder and SendPayloadBuilder."""

from __future__ import annotations

import warnings
from pathlib import Path

import pytest

from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
from mailjet_rest.types import SendV31Message


def test_message_builder_variables_size_limit() -> None:
    """Verify blocking of excessively large Variables objects to prevent Out-Of-Memory (OOM) errors."""
    builder = MessageBuilder()
    large_payload = {"huge_key": "x" * (1024 * 1024 + 100)}

    builder._payload = {
        "From": {"Email": "sender@example.com", "Name": "System"},
        "To": [{"Email": "recipient@example.com"}],
        "TextPart": "Hello",
        "Variables": large_payload,
    }

    with pytest.raises(ValueError, match="Security Violation"):
        builder.build()


def test_message_builder_variables_safe_size() -> None:
    """Verify that a valid, safe-sized Variables object passes validation without errors."""
    builder = MessageBuilder()

    builder._payload = {
        "From": {"Email": "sender@example.com", "Name": "System"},
        "To": [{"Email": "recipient@example.com"}],
        "TextPart": "Hello",
        "Variables": {"small_key": "safe_value"},
    }

    result = builder.build()
    assert "Variables" in result
    assert "From" in result
    assert "To" in result
    assert "TextPart" in result


def test_message_builder_validation_fails() -> None:
    """Verify that incomplete payloads fail early."""
    builder = MessageBuilder()
    with pytest.raises(ValueError, match="Sender \\(From\\) is required"):
        builder.build()


def test_message_builder_optional_branches(tmp_path: Path) -> None:
    """Test CC, BCC, HTML, TemplateID, and Attachments branches using safe sandbox paths."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")
    builder.add_recipient("to@example.com")
    builder.add_cc("cc@example.com", "CC Name")
    builder.add_bcc("bcc@example.com", "BCC Name")
    builder.set_subject("Test Subject")
    builder.set_content(text="Plain Text")
    builder.set_content(html="<h1>HTML</h1>")
    builder.set_template(12345)

    safe_file = tmp_path / "dummy.txt"
    safe_file.write_text("dummy content")

    builder.attach_file(safe_file, base_dir=tmp_path)
    res = builder.build()
    assert "Attachments" in res
    assert res["Attachments"][0]["Filename"] == "dummy.txt"


def test_message_builder_exhaustive_coverage() -> None:
    """Coverage: Force evaluation of all edge cases."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com", "Sender Name")
    builder.add_recipient("to@example.com")
    builder.set_variables({"key": "value"})
    builder._payload["TextPart"] = "Text"

    res = builder.build()
    assert res["Variables"]["key"] == "value"


def test_send_payload_builder_exhaustive() -> None:
    """Coverage: Verify root-level properties in SendPayloadBuilder."""
    msg_builder = MessageBuilder()
    msg_builder.set_sender("test@test.com")
    msg_builder.add_recipient("to@test.com")
    msg_builder._payload["TextPart"] = "Text"

    payload_builder = SendPayloadBuilder()
    payload_builder.add_message(msg_builder)
    payload_builder.set_sandbox_mode(True)
    payload_builder.set_globals({"Subject": "Global Subject"})

    res = payload_builder.build()
    assert res["SandboxMode"] is True
    assert res["Globals"]["Subject"] == "Global Subject"
    assert len(res["Messages"]) == 1


def test_message_builder_attachments_branches(tmp_path: Path) -> None:
    """Coverage: Tests attachment parsing and encoding inside the MessageBuilder using safe paths."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")
    builder.add_recipient("to@example.com")
    builder.add_cc("cc@example.com")
    builder.add_bcc("bcc@example.com")

    safe_file = tmp_path / "invoice.txt"
    safe_file.write_text("amount,date\n100,2023-01-01")

    builder.attach_inline(safe_file, base_dir=tmp_path)
    builder.set_content(html="<b>html</b>")

    res = builder.build()
    assert "InlinedAttachments" in res


def test_message_builder_optional_args_branches(tmp_path: Path) -> None:
    """Verify attachments can be stacked seamlessly."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")
    builder.add_recipient("to@example.com")
    builder.add_cc("cc@example.com")
    builder.add_bcc("bcc@example.com")

    safe_file = tmp_path / "invoice.txt"
    safe_file.write_text("content")

    builder.attach_inline(safe_file, base_dir=tmp_path)
    builder.attach_inline(safe_file, base_dir=tmp_path)

    builder.set_content(html="<b>html</b>")
    res = builder.build()
    assert len(res["InlinedAttachments"]) == 2


def test_message_builder_missing_names_and_recipients() -> None:
    """Coverage: Test branches where optional Name parameters are omitted."""
    builder = MessageBuilder()
    builder.set_sender("sender@test.com")
    builder.add_recipient("to@test.com")
    builder.add_cc("cc@test.com")
    builder.add_bcc("bcc@test.com")
    builder.set_reply_to("reply@test.com")

    builder.set_content(text="Hello")

    res = builder.build()
    assert "Name" not in res["From"]
    assert "Name" not in res["To"][0]
    assert "Name" not in res["Cc"][0]
    assert "Name" not in res["Bcc"][0]
    assert "Name" not in res["ReplyTo"]


def test_message_builder_no_recipients() -> None:
    """Coverage: Test validation branch for missing recipients."""
    builder = MessageBuilder()
    builder.set_sender("sender@test.com")
    builder.set_content(text="Hello")
    with pytest.raises(ValueError, match="At least one recipient"):
        builder.build()


def test_send_payload_builder_empty() -> None:
    """Coverage: Test SendPayloadBuilder validation branch."""
    builder = SendPayloadBuilder()
    with pytest.raises(ValueError, match="At least one message is required"):
        builder.build()


def test_message_builder_content_type_attachment(tmp_path: Path) -> None:
    """Coverage: Branch where an explicit Content-Type is provided to attach_file."""
    builder = MessageBuilder()
    builder.set_sender("test@test.com")

    builder.add_recipient("to@test.com")

    safe_file = tmp_path / "data.csv"
    safe_file.write_text("a,b,c")
    builder.attach_file(safe_file, content_type="text/csv", base_dir=tmp_path)
    builder.set_content(text="test")
    res = builder.build()
    assert res["Attachments"][0]["ContentType"] == "text/csv"


def test_message_builder_html_size_limit() -> None:
    """Coverage: HTML size strict upper bounds."""
    builder = MessageBuilder()
    builder.set_sender("test@test.com")
    builder.add_recipient("to@test.com")
    builder.set_content(html="x" * (6 * 1024 * 1024))
    with pytest.raises(ValueError, match="HTMLPart exceeds 5MB"):
        builder.build()


def test_message_builder_text_size_limit() -> None:
    """Coverage: Text size strict upper bounds."""
    builder = MessageBuilder()
    builder.set_sender("test@test.com")
    builder.add_recipient("to@test.com")
    builder.set_content(text="x" * (6 * 1024 * 1024))
    with pytest.raises(ValueError, match="TextPart exceeds 5MB"):
        builder.build()


def test_rfc8058_unsubscribe_tracking_and_deepcopy() -> None:
    """Verify RFC 8058 headers, tracking/custom_id validation, and deep copy isolation."""
    mb = (
        MessageBuilder()
        .set_sender("sender@example.com", "Sender")
        .add_recipient("to@example.com")
        .set_subject("Hello")
        .set_content(text="plain body")
        .set_custom_id("order-123")
        .set_event_payload('{"order":123}')
        .set_tracking(opens="enabled", clicks="disabled")
        .set_variables({"nested": {"k": "v"}})
        .set_list_unsubscribe("https://example.com/unsub?t=abc", mailto_address="unsub@example.com")
    )
    built = mb.build()
    headers = built.get("Headers")
    assert headers is not None
    assert headers["List-Unsubscribe"] == "<https://example.com/unsub?t=abc>, <mailto:unsub@example.com>"
    assert headers["List-Unsubscribe-Post"] == "List-Unsubscribe=One-Click"
    assert built.get("CustomID") == "order-123"
    assert built.get("TrackOpens") == "enabled"
    assert built.get("TrackClicks") == "disabled"

    # Mutating built result does not mutate internal builder state
    variables = built.get("Variables")
    assert variables is not None
    variables["nested"]["k"] = "mutated"
    built["To"].append({"Email": "extra@example.com"})
    rebuilt = mb.build()
    rebuilt_vars = rebuilt.get("Variables")
    assert rebuilt_vars is not None
    assert rebuilt_vars["nested"]["k"] == "v"
    assert len(rebuilt["To"]) == 1

    # Non-HTTPS and CRLF rejected
    with pytest.raises(ValueError, match="https://"):
        mb.set_list_unsubscribe("http://example.com/unsub")
    with pytest.raises(ValueError, match="CWE-93"):
        mb.set_list_unsubscribe("https://example.com/unsub\r\nX-Evil: 1")
    with pytest.raises(ValueError, match="TrackOpens"):
        mb.set_tracking(opens="invalid")  # type: ignore[arg-type]


def test_inline_cid_and_gmail_102kb_warning(tmp_path: Path) -> None:
    """Verify inline ContentID, missing CID warning, and 102 KB Gmail clipping warning."""
    logo = tmp_path / "logo.png"
    logo.write_bytes(b"\x89PNG\r\n\x1a\nlogo")

    # Matching ContentID emits zero warning
    clean_builder = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .attach_inline(logo, content_type="image/png", base_dir=tmp_path, content_id="logo-cid")
        .set_content(html='<img src="cid:logo-cid">')
    )
    clean_msg = clean_builder.build()
    inlined = clean_msg.get("InlinedAttachments")
    assert inlined is not None
    assert inlined[0].get("ContentID") == "logo-cid"

    # Missing CID reference warns
    missing_cid = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(html='<img src="cid:missing-cid">')
    )
    with pytest.warns(UserWarning, match="missing-cid"):
        missing_cid.build()

    # >102 KB HTML warns about Gmail clipping
    large_html = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(html="<p>" + ("a" * (110 * 1024)) + "</p>")
    )
    with pytest.warns(UserWarning, match="102 KB"):
        large_html.build()


def test_send_payload_and_template_batch_limits() -> None:
    """Verify SendPayloadBuilder 50-message limit, 15MB cap, and TemplateContentBuilder deepcopy."""
    msg = (
        MessageBuilder().set_sender("sender@example.com").add_recipient("to@example.com").set_content(text="hi").build()
    )

    batch = SendPayloadBuilder()
    for _ in range(50):
        batch.add_message(msg)
    built_batch = batch.build()
    assert len(built_batch["Messages"]) == 50

    with pytest.raises(ValueError, match="at most 50"):
        batch.add_message(msg)

    # 15MB total payload limit check
    huge_text = "x" * (4 * 1024 * 1024)
    big_msg = (
        MessageBuilder()
        .set_sender("sender@example.com")
        .add_recipient("to@example.com")
        .set_content(text=huge_text)
        .build()
    )
    oversize_batch = SendPayloadBuilder()
    for _ in range(4):
        oversize_batch.add_message(big_msg)
    with pytest.raises(ValueError, match="15MB"):
        oversize_batch.build()

    tb = TemplateContentBuilder().set_meta(author="Alice").set_content(text="body").set_headers({"X-A": "1"})
    t_payload = tb.build()
    t_payload["Headers"]["X-A"] = "mutated"
    assert tb.build()["Headers"]["X-A"] == "1"


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


def test_message_builder_set_template_rejects_invalid_ids_and_flags() -> None:
    """MessageBuilder.set_template must reject booleans, non-positive IDs, and non-bool flags."""
    mb = MessageBuilder()
    for bad_id in (True, False, 0, -5, "123"):
        with pytest.raises((ValueError, TypeError)):
            mb.set_template(bad_id)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="language_active must be a bool"):
        mb.set_template(12345, language_active="yes")  # type: ignore[arg-type]


def test_message_builder_set_template_defaults_and_error_messages() -> None:
    """Kill survived mutants in MessageBuilder.set_template."""
    mb = MessageBuilder().set_sender("a@example.com").add_recipient("b@example.com").set_template(1)
    built = mb.build()
    assert built.get("TemplateID") == 1
    assert built.get("TemplateLanguage") is True

    with pytest.raises(ValueError, match="template_id must be a strictly positive integer, got 0"):
        MessageBuilder().set_template(0)

    with pytest.raises(TypeError, match="language_active must be a bool, got str"):
        MessageBuilder().set_template(1, "yes")  # type: ignore[arg-type]
