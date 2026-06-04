import os
import tempfile

import pytest
from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder


def test_message_builder_variables_size_limit() -> None:
    """Verify blocking of excessively large Variables objects to prevent Out-Of-Memory (OOM) errors."""
    builder = MessageBuilder()

    # Create a dictionary that exceeds 1MB when JSON-serialized
    large_payload = {"huge_key": "x" * (1024 * 1024 + 100)}

    builder._msg = {
        "From": {"Email": "sender@example.com", "Name": "System"},
        "To": [{"Email": "recipient@example.com"}],
        "TextPart": "Hello",
        "Variables": large_payload,
    }

    with pytest.raises(ValueError, match="Security Violation: Variables payload too large"):
        builder.build()


def test_message_builder_variables_safe_size() -> None:
    """Verify that a valid, safe-sized Variables object passes validation without errors."""
    builder = MessageBuilder()

    builder._msg = {
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
    """Verify correct mapping to Template Content API schema (hyphenated keys)."""
    builder = TemplateContentBuilder()

    payload = (
        builder
        .set_content(text="Plain text", html="<h1>Hello</h1>", mjml="<mjml></mjml>")
        .set_headers({"Reply-To": "support@example.com"})
        .build()
    )

    # Check for correct hyphenated keys required by the Template API
    assert payload.get("TextPart") == "Plain text"
    assert payload.get("HTMLPart") == "<h1>Hello</h1>"
    assert payload.get("MJMLContent") == "<mjml></mjml>"
    assert payload.get("Headers") == {"Reply-To": "support@example.com"}


def test_template_content_builder_partial_data() -> None:
    """Verify that builder only includes provided fields."""
    builder = TemplateContentBuilder()
    payload = builder.set_content(text="Just text").build()

    assert "TextPart" in payload
    assert "HTMLPart" not in payload
    assert "MJMLContent" not in payload


def test_message_builder_validation_fails() -> None:
    """Test validation errors when building an incomplete message."""
    builder = MessageBuilder()
    builder.add_recipient("to@example.com")
    # Fails because 'From' sender is missing
    with pytest.raises(ValueError):
        builder.build()

def test_message_builder_optional_branches() -> None:
    """Test CC, BCC, HTML, TemplateID, and Attachments branches."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")
    builder.add_recipient("to@example.com")
    builder.add_cc("cc@example.com", "CC Name")
    builder.add_bcc("bcc@example.com", "BCC Name")
    builder.set_subject("Test Subject")
    builder.set_content(text="Plain Text")
    builder.set_content(html="<h1>HTML</h1>")
    builder.set_template(12345)

    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(b"dummy content")
        tmp_name = tmp.name

    try:
        builder.attach_file(tmp_name)
    finally:
        os.remove(tmp_name)

    result = builder.build()

    assert "To" in result
    assert len(result.get("To", [])) >= 1
    assert "Subject" in result

def test_template_content_builder_validation_fails() -> None:
    """Fails because neither Text, HTML, nor MJML is provided."""
    builder = TemplateContentBuilder()
    with pytest.raises(ValueError, match="At least one of text, html, or mjml content is required"):
        builder.build()


def test_message_builder_exhaustive_coverage() -> None:
    """Test all branches of MessageBuilder to maximize coverage."""
    builder = MessageBuilder()

    # Sender with name (hits 'if name:' branch)
    builder.set_sender("sender@example.com", name="Sender Name")

    # ReplyTo with name
    if hasattr(builder, "set_reply_to"):
        builder.set_reply_to("reply@example.com", name="Reply Name")

    # Multiple recipients with names (hits both initialization and append branches)
    builder.add_recipient("to1@example.com", name="To1")
    builder.add_recipient("to2@example.com", name="To2")

    # Multiple CCs with names
    builder.add_cc("cc1@example.com", name="CC1")
    builder.add_cc("cc2@example.com", name="CC2")

    # Multiple BCCs with names
    builder.add_bcc("bcc1@example.com", name="BCC1")
    builder.add_bcc("bcc2@example.com", name="BCC2")

    builder.set_subject("Test Exhaustive")

    # Content with text and html
    builder.set_content(text="Text", html="<b>HTML</b>")

    # Additional dictionary-based settings
    if hasattr(builder, "set_variables"):
        builder.set_variables({"var1": "val1"})
    if hasattr(builder, "set_globals"):
        builder.set_globals({"glob1": "val1"})
    if hasattr(builder, "set_headers"):
        builder.set_headers({"X-Header": "Value"})

    res = builder.build()

    assert res.get("From", {}).get("Name") == "Sender Name"  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert len(res.get("To", [])) == 2
    assert res.get("To", [{}, {}])[1].get("Name") == "To2"  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert len(res.get("Cc", [])) == 2  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert res.get("Cc", [{}])[0].get("Name") == "CC1"  # type: ignore[call-overload]  # pyright: ignore[reportTypedDictNotRequiredAccess]
    assert len(res.get("Bcc", [])) == 2  # pyright: ignore[reportTypedDictNotRequiredAccess]

def test_template_content_builder_exhaustive() -> None:
    """Test TemplateContentBuilder with all optional parameters."""
    builder = TemplateContentBuilder()
    builder.set_meta(author="Author", name="Name")

    # Passing all 3 parts ensures no missing branches inside set_content
    builder.set_content(text="Text", html="HTML", mjml="MJML")
    builder.set_headers({"Key": "Val"})

    res = builder.build()
    assert res.get("TextPart") == "Text"
    assert res.get("HTMLPart") == "HTML"
    assert res.get("MJMLContent") == "MJML"
    assert res.get("Headers", {}).get("Key") == "Val"

def test_message_builder_attachments_branches() -> None:
    """Hit branches for multiple attachments."""
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")  # <-- Added missing sender
    builder.add_recipient("to@example.com")
    builder.set_content(text="Hello")

    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"attachment1")
        tmp1_name = tmp.name

    try:
        # First call initializes the list inside _msg
        builder.attach_file(tmp1_name)
        # Second call hits the append branch
        builder.attach_file(tmp1_name)

        # Test inline attachments if the method exists
        if hasattr(builder, "attach_inline"):
            builder.attach_inline(tmp1_name)
            builder.attach_inline(tmp1_name)
    finally:
        os.remove(tmp1_name)

    res = builder.build()
    assert len(res.get("Attachments", [])) == 2  # pyright: ignore[reportTypedDictNotRequiredAccess]
    if hasattr(builder, "attach_inline"):
        assert len(res.get("InlinedAttachments", [])) == 2  # type: ignore[arg-type]  # pyright: ignore[reportTypedDictNotRequiredAccess]


def test_message_builder_missing_to_raises() -> None:
    builder = MessageBuilder()
    builder.set_sender("test@example.com")
    with pytest.raises(ValueError, match="At least one recipient \\(To\\) is required"):
        builder.build()

    builder._msg["To"] = []
    with pytest.raises(ValueError, match="At least one recipient \\(To\\) is required"):
        builder.build()

def test_message_builder_missing_content_raises() -> None:
    builder = MessageBuilder()
    builder.set_sender("test@example.com")
    builder.add_recipient("test@example.com")
    with pytest.raises(ValueError, match="Message validation failed: TextPart, HTMLPart, or TemplateID is required."):
        builder.build()

def test_message_builder_optional_args_branches() -> None:
    builder = MessageBuilder()
    builder.set_sender("sender@example.com")  # No name provided
    if hasattr(builder, "set_reply_to"):
        builder.set_reply_to("reply@example.com")  # No name provided
    builder.add_recipient("to@example.com")  # No name provided
    builder.add_cc("cc@example.com")  # No name provided
    builder.add_bcc("bcc@example.com")  # No name provided

    import tempfile
    import os
    with tempfile.NamedTemporaryFile(delete=False, suffix=".txt") as tmp:
        tmp.write(b"attachment1")
        tmp1_name = tmp.name
    try:
        if hasattr(builder, "attach_inline"):
            # First call initializes the array branch
            builder.attach_inline(tmp1_name)
            # Second call hits the append branch
            builder.attach_inline(tmp1_name)
    finally:
        os.remove(tmp1_name)

    builder.set_content(html="<b>html</b>")
    res = builder.build()
    assert "Name" not in res.get("From", {})
    assert "Name" not in res.get("To", [{}])[0]


def test_template_content_builder_empty_build() -> None:
    builder = TemplateContentBuilder()
    with pytest.raises(ValueError, match="At least one of text, html, or mjml content is required"):
        builder.build()

def test_template_content_builder_partial_content() -> None:
    # Test setting each type exclusively to cover the 3 isolated IF branches
    builder1 = TemplateContentBuilder().set_content(text="text")
    assert "TextPart" in builder1.build()

    builder2 = TemplateContentBuilder().set_content(html="html")
    assert "HTMLPart" in builder2.build()

    builder3 = TemplateContentBuilder().set_content(mjml="mjml")
    assert "MJMLContent" in builder3.build()
