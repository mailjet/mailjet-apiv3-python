from typing import Any, cast

import pytest
import logging
from unittest.mock import patch

from mailjet_rest import Client
from mailjet_rest.utils.guardrails import SecurityGuard, RedactingFilter, \
    SecureHTTPAdapter


@pytest.fixture
def client_offline() -> Client:
    """Local fixture to provide a basic Client instance."""
    from mailjet_rest.client import Client
    return Client(auth=("test", "test"))


def test_security_guard_crlf_rejection_fast_regex() -> None:
    """Verify that the pre-compiled regex efficiently blocks CRLF injections."""
    # Test Carriage Return + Line Feed
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\r\ninjected"})

    # Test Line Feed only
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\n"})

    # Test Carriage Return only
    with pytest.raises(ValueError, match="CRLF Injection detected in header 'X-Custom'"):
        SecurityGuard.validate_crlf_headers({"X-Custom": "value\r"})

    # Should not raise
    SecurityGuard.validate_crlf_headers({"X-Custom": "safe-value"})


def test_validate_config_url_malicious_domain() -> None:
    with pytest.raises(ValueError, match="not a trusted Mailjet domain"):
        SecurityGuard.validate_config_url("https://attacker.com/v3")


def test_redacting_filter_scrubs_message_string() -> None:
    """Verify that secrets in the main log message are redacted in memory (CWE-312)."""
    redactor = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.DEBUG, pathname="", lineno=0,
        msg="Failed request with Authorization: Bearer sk_live_super_secret_token",
        args=(), exc_info=None
    )

    redactor.filter(record)

    assert "live_super_secret_token" not in record.msg
    assert "********" in record.msg
    assert "Authorization: Bearer ********" in record.msg


def test_redacting_filter_scrubs_log_arguments() -> None:
    """Verify that secrets passed as *args to the logger are redacted."""
    redactor = RedactingFilter()
    record = logging.LogRecord(
        name="test", level=logging.DEBUG, pathname="", lineno=0,
        msg="Payload data: %s",
        args=("api_key: pub_key_12345",), exc_info=None
    )

    redactor.filter(record)

    args = cast(tuple[Any, ...], record.args)
    msg = str(args[0]) if args else ""
    assert "pub_key_12345" not in msg
    assert "api_key: ********" in msg

def test_redacting_filter_complex_secrets() -> None:
    """Verify redaction of various Auth patterns (Bearer, Basic, API Keys)."""
    redactor = RedactingFilter()

    test_cases = [
        ("Authorization: Bearer foo_live_12345", "Authorization: Bearer ********"),
        ("api_key: bar_live_abcde", "api_key: ********"),
        ("api_secret=foo_test_54321", "api_secret=********"),
    ]

    for input_str, expected in test_cases:
        record = logging.LogRecord(
            name="test", level=logging.DEBUG, pathname="", lineno=0,
            msg=input_str, args=(), exc_info=None
        )
        redactor.filter(record)
        assert expected in record.msg
        assert "foo_live_12345" not in record.msg


def test_logger_has_redacting_filter() -> None:
    """Ensure the RedactingFilter is active in the logger."""
    # Access the private logger instance
    logger = logging.getLogger("mailjet_rest.client")
    has_filter = any(isinstance(f, RedactingFilter) for f in logger.filters)
    assert has_filter, "RedactingFilter is not attached to the logger!"


def test_stream_only_allows_get(client_offline: Client) -> None:
    """Verify that stream() strictly enforces GET requests."""
    with pytest.raises(ValueError, match="stream.* designed for GET requests only"):
        list(client_offline.contact.stream(method="POST"))


def test_security_audit_listener_logs_mailjet_events(caplog: pytest.LogCaptureFixture) -> None:
    """Verify that the audit listener logs only 'mailjet.*' events."""
    caplog.set_level(logging.WARNING)

    # Simulate sys.audit emitting a Mailjet event
    SecurityGuard._security_audit_listener("mailjet.security.test", ("arg1", "arg2"))
    assert "SECURITY AUDIT [mailjet.security.test]" in caplog.text

    # Simulate sys.audit emitting a system event (should be ignored)
    caplog.clear()
    SecurityGuard._security_audit_listener("os.system", ("echo",))
    assert "SECURITY AUDIT" not in caplog.text


@patch("sys.addaudithook")
def test_enable_audit_logging_registers_hook(mock_add_hook: Any) -> None:
    """Verify the hook registration logic and idempotency flag."""
    # Reset internal state for isolated testing
    SecurityGuard._audit_hook_installed = False

    # First call should register the hook
    SecurityGuard.enable_audit_logging()
    mock_add_hook.assert_called_once_with(SecurityGuard._security_audit_listener)
    assert SecurityGuard._audit_hook_installed is True

    # Second call should NOT register it again (Idempotency)
    mock_add_hook.reset_mock()
    SecurityGuard.enable_audit_logging()
    mock_add_hook.assert_not_called()

def test_validate_config_url_http() -> None:
    """Rejects cleartext HTTP."""
    # Updated the match string to reflect the actual error thrown by guardrails.py
    with pytest.raises(ValueError, match="Security Violation: api_url scheme must be 'HTTPS'"):
        SecurityGuard.validate_config_url("http://api.mailjet.com/v3")
def test_check_file_size_exceeded(tmp_path: Any) -> None:
    """Rejects files larger than max_size_bytes."""
    test_file = tmp_path / "large_file.txt"
    test_file.write_bytes(b"x" * 1024)
    with pytest.raises(ValueError, match="exceeds the safe threshold"):
        SecurityGuard.check_file_size(test_file, max_size_bytes=500)

def test_sanitize_segment_none() -> None:
    """Handles None gracefully."""
    assert SecurityGuard.sanitize_segment(None) == ""

def test_redacting_filter_hides_authorization() -> None:
    """Secret hiding inside logging formatter."""
    filter_instance = RedactingFilter()
    record = logging.LogRecord(
        name="test_logger", level=logging.INFO, pathname="", lineno=0,
        msg="Attempting to auth with Header Authorization: Bearer secret_12345_token",
        args=(), exc_info=None
    )
    filter_instance.filter(record)
    assert "secret_12345_token" not in record.msg
    assert "***" in record.msg

def test_redacting_filter_ignores_non_strings() -> None:
    """Ignore filtering on non-string dict messages."""
    filter_instance = RedactingFilter()
    record = logging.LogRecord(
        name="test_logger", level=logging.INFO, pathname="", lineno=0,
        msg={"dict": "payload"}, args=(), exc_info=None
    )
    assert filter_instance.filter(record) is True

def test_sanitize_log_trace_non_string() -> None:
    # Ensure non-string values pass through correctly
    assert SecurityGuard.sanitize_log_trace(123) == "123"
    assert SecurityGuard.sanitize_log_trace({"a": 1}) == "{'a': 1}"

def test_validate_config_url_valid() -> None:
    # Ensure valid URLs don't trigger exception branches
    SecurityGuard.validate_config_url("https://api.mailjet.com/v3")

def test_validate_attribute_access_valid() -> None:
    SecurityGuard.validate_attribute_access("Client", "valid_attribute")

def test_secure_http_adapter_coverage() -> None:
    adapter = SecureHTTPAdapter()
    assert adapter is not None
    # We just need to trigger the init_poolmanager method to cover the lines
    adapter.init_poolmanager(connections=1, maxsize=1)
