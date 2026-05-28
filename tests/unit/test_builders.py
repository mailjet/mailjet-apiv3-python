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
    assert payload["TextPart"] == "Plain text"
    assert payload["HTMLPart"] == "<h1>Hello</h1>"
    assert payload["MJMLPart"] == "<mjml></mjml>"
    assert payload["Headers"] == {"Reply-To": "support@example.com"}

def test_template_content_builder_partial_data() -> None:
    """Verify that builder only includes provided fields."""
    builder = TemplateContentBuilder()
    payload = builder.set_content(text="Just text").build()

    assert "TextPart" in payload
    assert "HTMLPart" not in payload
    assert "MJMLPart" not in payload
