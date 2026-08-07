# pyright: reportIndexIssue=false
"""Unit tests for the guardrails.py security module."""

import logging
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.utils.guardrails import RedactingFilter, SecretAuth, SecurityGuard


class TestRedactingFilter:
    def test_redacting_filter_scrubs_secrets_from_string(self) -> None:
        """Coverage: Hits the string redaction branch."""
        filter_ = RedactingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Sending payload with api_key: Bearer 12345secret",
            args=(),
            exc_info=None,
        )
        filter_.filter(record)
        assert "12345secret" not in str(record.msg)
        assert "********" in str(record.msg)

    def test_deep_redact_scrubs_nested_dictionaries(self) -> None:
        """Coverage: Hits the deep recursion branches with nested objects."""
        filter_ = RedactingFilter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Raw request args",
            # We inject the full matching pattern into the value so the string redactor sees context
            args=({"headers": {"Authorization": "Authorization: Basic mysecretkey"}},),
            exc_info=None,
        )
        filter_.filter(record)
        assert isinstance(record.args, dict)
        assert "mysecretkey" not in record.args["headers"]["Authorization"]
        assert "********" in record.args["headers"]["Authorization"]

    def test_deep_redact_stops_at_max_depth(self) -> None:
        """Coverage: Hits the MAX_REDACTION_DEPTH failsafe."""
        filter_ = RedactingFilter()
        deep_dict = {"a": {"b": {"c": {"d": {"e": "too_deep"}}}}}

        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Deep structure",
            args=(deep_dict,),
            exc_info=None,
        )
        filter_.filter(record)
        assert isinstance(record.args, dict)
        assert record.args["a"]["b"]["c"]["d"]["e"] == "[MAX_DEPTH_REACHED]"


class TestSecurityGuard:
    def test_validate_config_url_valid(self) -> None:
        """Coverage: Valid URL passes cleanly."""
        SecurityGuard.validate_config_url("https://api.mailjet.com/v3", "mailjet.com")

    def test_validate_config_url_http(self) -> None:
        """Coverage: Invalid scheme is blocked (CWE-918)."""
        with pytest.raises(ValueError, match="Invalid scheme 'ftp'"):
            SecurityGuard.validate_config_url("ftp://api.mailjet.com")

    def test_validate_config_url_malicious_domain(self) -> None:
        """Coverage: Unrecognized domains blocked (CWE-918)."""
        with pytest.raises(ValueError, match="not permitted"):
            SecurityGuard.validate_config_url("https://attacker.com/v3", "mailjet.com")

    def test_sanitize_headers_catches_crlf(self) -> None:
        """Coverage: HTTP Header Injection (CWE-113)."""
        with pytest.raises(ValueError, match="CRLF injection"):
            SecurityGuard.sanitize_headers({"X-Custom": "val\r\ninjected"})

    def test_check_control_characters(self) -> None:
        """Coverage: Null byte injection (CWE-20)."""
        with pytest.raises(ValueError, match="Unprintable control character"):
            SecurityGuard.check_control_characters("field", "bad\x00string")

    def test_analyze_html_safety_blocks_xss(self) -> None:
        """Coverage: SpamGuard catches script tags."""
        with pytest.raises(ValueError, match="executable Javascript/XSS vectors"):
            SecurityGuard.analyze_html_safety("<script>alert(1)</script>")

    def test_analyze_html_safety_blocks_events(self) -> None:
        """Coverage: SpamGuard catches inline events."""
        with pytest.raises(ValueError, match="blocked script/event execution tags"):
            SecurityGuard.analyze_html_safety("<img src='x' onerror='alert(1)'>")

    def test_generate_payload_fingerprint(self) -> None:
        """Coverage: Idempotency hashing mechanism."""
        payload1 = {"a": 1, "b": 2, "CustomID": "ignore"}
        payload2 = {"b": 2, "a": 1, "EventPayload": "ignore"}
        assert SecurityGuard.generate_payload_fingerprint(payload1) == SecurityGuard.generate_payload_fingerprint(
            payload2
        )

    def test_validate_attachment_path_traversal(self, tmp_path: Path) -> None:
        """Coverage: Path traversal enforcement (CWE-22)."""
        # The check ordering now evaluates bounds before touching the filesystem,
        # throwing the correct security error!
        with pytest.raises(ValueError, match="Traversal detected"):
            SecurityGuard.validate_attachment_path("../../etc/passwd", tmp_path)

    def test_check_file_size_exceeded(self, tmp_path: Path) -> None:
        """Coverage: Hits CWE-400 resource exhaustion."""
        test_file = tmp_path / "large.txt"
        test_file.write_bytes(b"0" * 1025)
        with pytest.raises(ValueError, match="exceeds safe threshold"):
            SecurityGuard.check_file_size(test_file, max_size_bytes=1000)

    def test_validate_timeout_nan_inf(self) -> None:
        """Coverage: CWE-400 Float evaluation."""
        with pytest.raises(ValueError, match="Timeout cannot be Infinity or NaN"):
            SecurityGuard.validate_timeout(float("inf"))

    def test_normalize_domain_punycode(self) -> None:
        """Coverage: IDN homograph normalization."""
        puny = SecurityGuard.normalize_domain("info@münchen.de")
        assert puny == "info@xn--mnchen-3ya.de"

    def test_sanitize_log_trace(self) -> None:
        """Coverage: CWE-117 Log Forging."""
        clean = SecurityGuard.sanitize_log_trace("My\nTrace\rID")
        assert clean == "My_Trace_ID"

    @patch("sys.audit")
    def test_audit_hooks_are_emitted(self, mock_audit: MagicMock) -> None:
        """Coverage: PEP 578 integration."""
        with pytest.raises(ValueError, match="Path traversal attempt"):
            SecurityGuard.sanitize_segment("..")
        mock_audit.assert_called_with("mailjet.security.path_traversal", "..")


def test_generate_payload_fingerprint_cyclic() -> None:
    """Coverage: Prevent recursion errors on cyclic references."""
    cyclic: dict[str, Any] = {}
    cyclic["a"] = cyclic
    # Should gracefully return a string hash without crashing
    assert SecurityGuard.generate_payload_fingerprint(cyclic)


def test_generate_payload_fingerprint_max_depth() -> None:
    """Coverage: Enforce maximum nesting depth limits."""
    deep: Any = {"a": 1}
    for _ in range(55):
        deep = {"a": deep}

    with pytest.raises(ValueError, match="Payload hashing failed due to malformed"):
        SecurityGuard.generate_payload_fingerprint(deep)


def test_validate_attachment_path_no_sandbox() -> None:
    """Coverage: Fallback zero-trust checks for OS roots and path traversal."""
    with pytest.raises(ValueError, match="Path traversal tokens"):
        SecurityGuard.validate_attachment_path("../etc/passwd")

    with pytest.raises(ValueError, match="explicitly forbidden"):
        SecurityGuard.validate_attachment_path("/etc/passwd")


def test_sanitize_segment_template_injection() -> None:
    """Coverage: Block Jinja/Template injection signatures."""
    with pytest.raises(ValueError, match="Template injection attempt"):
        SecurityGuard.sanitize_segment("{{ config.secret }}")


def test_sanitize_segment_invalid_type() -> None:
    """Coverage: Block dicts/lists in path segments."""
    with pytest.raises(TypeError, match="Invalid segment type"):
        SecurityGuard.sanitize_segment({"dict": "not allowed"})  # type: ignore[arg-type]


def test_spam_guard_html_analysis_htmlparser_error() -> None:
    """Coverage: Trigger Failsafe on HTMLParser crash."""

    class CrashParser(HTMLParser):
        def feed(self, data: str) -> None:
            raise RecursionError("Simulated crash")

    with patch.object(SecurityGuard, "_SpamGuardParser", CrashParser):
        with pytest.raises(Exception, match="Fatal HTML parsing error"):
            SecurityGuard.analyze_html_safety("<div></div>")


def test_secretauth_repr() -> None:
    """Coverage: Confirm string representations scrub memory securely."""
    auth = SecretAuth(("user", "pass"))
    assert repr(auth) == "SecretAuth(***REDACTED***)"


def test_redacting_filter_exceptions(monkeypatch: pytest.MonkeyPatch) -> None:
    """Coverage: Trigger string parsing failures inside logging filter."""
    filter_ = RedactingFilter()

    # Create a mock pattern object to bypass re.Pattern immutability
    class MockPattern:
        def sub(self, *args: Any, **kwargs: Any) -> str:
            raise ValueError("Forced error")

    # Mock the internal function returning the pattern instead of the pattern type itself
    monkeypatch.setattr("mailjet_rest.utils.guardrails._get_secret_pattern", lambda: MockPattern())

    # It should catch the error and return the original string transparently
    assert RedactingFilter._redact_str("test") == "[REDACTION_FAILED_UNSAFE_STRING]"

    # It should catch any error in the outer filter() block and return True (allow log writing)
    record = logging.LogRecord("test", logging.INFO, "", 0, "msg", (), None)
    assert filter_.filter(record) is True


def test_spam_guard_html_analysis_object_embed() -> None:
    """Coverage: Hit the alternate <object> and <embed> branches."""
    with pytest.raises(ValueError, match="Security Violation: HTML contains executable Javascript/XSS vectors."):
        SecurityGuard.analyze_html_safety("<object data='x'></object>")

    with pytest.raises(ValueError, match="Security Violation: HTML contains executable Javascript/XSS vectors."):
        SecurityGuard.analyze_html_safety("<embed src='x'></embed>")


def test_analyze_html_safety_whitespace() -> None:
    """Coverage: Immediate return on whitespace strings."""
    assert SecurityGuard.analyze_html_safety("   ")["is_safe"] is True


def test_validate_attachment_path_forbidden_components() -> None:
    """Coverage: Block access when crossing OS structural thresholds."""
    with pytest.raises(ValueError, match="explicitly forbidden"):
        SecurityGuard.validate_attachment_path("/a/windows/b.txt")


def test_sanitize_segment_double_encoding() -> None:
    """Coverage: Protects against double-encoded path traversal attacks (CWE-116)."""
    with pytest.raises(ValueError, match="Excessive URL encoding"):
        # Percent encode "%25" three times -> %252525 -> %2525 -> %25
        SecurityGuard.sanitize_segment("%2525252525")


def test_sanitize_segment_slashes() -> None:
    """Coverage: Verify unescaped path traversals in path generation are intercepted."""
    with pytest.raises(ValueError, match="Path traversal attempt"):
        SecurityGuard.sanitize_segment("a/b")
    with pytest.raises(ValueError, match="Path traversal attempt"):
        SecurityGuard.sanitize_segment("a\\b")


def test_sanitize_segment_xss() -> None:
    """Coverage: Prevent URL-based XSS injection via dynamically generated attributes."""
    with pytest.raises(ValueError, match="XSS attempt detected"):
        SecurityGuard.sanitize_segment("<script>")


def test_normalize_domain_exceptions() -> None:
    """Coverage: Ensure homograph IDNA encoder falls back securely on invalid bounds."""
    # IDNA has strict byte limits per label which will naturally force an exception
    with pytest.raises(ValueError, match="Invalid IDN in email"):
        SecurityGuard.normalize_domain("user@" + "x" * 1000)

    with pytest.raises(ValueError, match="Invalid IDN"):
        SecurityGuard.normalize_domain("x" * 1000)
