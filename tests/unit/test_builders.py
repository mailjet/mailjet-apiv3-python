import pytest
from mailjet_rest.builders import MessageBuilder


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
