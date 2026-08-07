# pyright: reportTypedDictNotRequiredAccess=false
"""Unit tests for the payload builder modules."""

import os
import tempfile
from pathlib import Path
import pytest
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder


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


def test_template_content_builder_mapping() -> None:
    """Verify correct payload assembly for templates."""
    builder = TemplateContentBuilder()
    builder.set_content(text="Hello", html="<b>Hello</b>", mjml="<mjml></mjml>")
    builder.set_headers({"X-Custom": "Value"})
    res = builder.build()
    assert res["Text-part"] == "Hello"
    assert res["Html-part"] == "<b>Hello</b>"
    assert res["Headers"]["X-Custom"] == "Value"


def test_template_content_builder_partial_data() -> None:
    """Verify partial content insertion."""
    builder = TemplateContentBuilder()
    builder.set_content(text="Only Text")
    res = builder.build()
    assert "Html-part" not in res
    assert res["Text-part"] == "Only Text"


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


def test_template_content_builder_validation_fails() -> None:
    """Verify empty template structures are blocked."""
    builder = TemplateContentBuilder()

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml content is required"):
        builder.build()


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


def test_template_content_builder_empty_build() -> None:
    """Verify empty template structures are rejected cleanly."""
    builder = TemplateContentBuilder()

    with pytest.warns(PendingDeprecationWarning, match="At least one of text, html, or mjml"):
        builder.build()


def test_template_content_builder_partial_content() -> None:
    """Verify partial builds render safely."""
    builder1 = TemplateContentBuilder().set_content(text="text")
    assert "Text-part" in builder1.build()

    builder2 = TemplateContentBuilder().set_content(html="html")
    assert "Html-part" in builder2.build()


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

def test_spam_guard_html_analysis(monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Enable spam guard analysis in MessageBuilder."""
    builder = MessageBuilder()

    # Use monkeypatch to modify the ClassVar since __slots__ prevents instance mutation
    monkeypatch.setattr(MessageBuilder, "ENABLE_SPAM_GUARD", True)

    # Mock the security guard to return a "not safe" analysis,
    # simulating a deliverability warning without throwing a hard security exception.
    monkeypatch.setattr(
        "mailjet_rest.builders.SecurityGuard.analyze_html_safety",
        lambda html: {"is_safe": False, "issues": ["Mocked deliverability issue"]}
    )

    with pytest.warns(UserWarning, match="Deliverability Warning"):
        builder.set_content(html="<div>Mocked HTML</div>")

def test_template_content_builder_full() -> None:
    """Coverage: Test TemplateContentBuilder meta and mjml properties."""
    builder = TemplateContentBuilder()
    builder.set_meta(author="Author Name", name="Template Name", locale="en-US")
    builder.set_content(mjml="<mjml><mjml-body></mjml-body></mjml>")
    res = builder.build()
    assert res["Author"] == "Author Name"
    assert res["Name"] == "Template Name"
    assert res["Locale"] == "en-US"
    assert res["MJMLContent"] == "<mjml><mjml-body></mjml-body></mjml>"

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


def test_template_content_builder_meta_branches() -> None:
    """Coverage: Test isolated template builder meta properties."""
    b1 = TemplateContentBuilder().set_meta(author="A")
    assert b1._payload["Author"] == "A"
    b2 = TemplateContentBuilder().set_meta(name="N")
    assert b2._payload["Name"] == "N"
    b3 = TemplateContentBuilder().set_meta(locale="L")
    assert b3._payload["Locale"] == "L"
