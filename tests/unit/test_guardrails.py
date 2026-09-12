# pyright: reportIndexIssue=false
"""Unit tests for the guardrails.py security module."""

from __future__ import annotations

import logging
import tempfile
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.utils.guardrails import (
    RedactingFilter,
    SecretAuth,
    SecureHTTPAdapter,
    SecurityGuard,
)


class TestRedactingFilter:
    """Test suite covering secret redaction across log strings, nested structures, and objects."""

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

    def test_redacting_filter_exceptions(self, monkeypatch: pytest.MonkeyPatch) -> None:
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

    def test_redacting_filter_advanced_types_and_extras(self) -> None:
        """Cover NamedTuples, sets, dataclass/object models, and extra attributes in logging."""
        filter_ = RedactingFilter()

        # 1. Custom objects with __dict__
        class CustomPayload:
            def __init__(self) -> None:
                self.api_key = "api_key: secret_token_value"  # pragma: allowlist secret

        # 2. Objects with model_dump (Pydantic style)
        class PydanticDummy:
            def model_dump(self) -> dict[str, str]:
                return {"token": "token 12345secret"}

        # 3. Set & frozenset redaction
        raw_set = {"api_key: set_secret"}
        raw_frozenset = frozenset(["api_key: frozenset_secret"])

        record = logging.LogRecord(
            name="test_logger",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="Logging structured records",
            args=(CustomPayload(), PydanticDummy(), raw_set, raw_frozenset),
            exc_info=None,
        )
        # Inject an 'extra' attribute containing key context
        record.custom_audit_field = {"header": "Authorization: Bearer secret_extra_token"}  # type: ignore[attr-defined]

        filter_.filter(record)

        # Validate redactions
        assert "secret_token_value" not in str(record.args)
        assert "12345secret" not in str(record.args)
        assert "set_secret" not in str(record.args)
        assert "frozenset_secret" not in str(record.args)
        assert "secret_extra_token" not in str(getattr(record, "custom_audit_field"))


class TestSecretAuth:
    """Test suite covering SecretAuth encapsulation, hashing, and memory protection."""

    def test_secretauth_repr(self) -> None:
        """Coverage: Confirm string representations scrub memory securely."""
        auth = SecretAuth(("user", "pass"))
        assert repr(auth) == "SecretAuth(***REDACTED***)"

    def test_secret_auth_security_boundaries(self) -> None:
        """Cover SecretAuth __hash__, __eq__, __getitem__, and __iter__ protections."""
        auth1 = SecretAuth(("user_key", "secret_pass"))
        auth2 = SecretAuth(("user_key", "secret_pass"))
        auth_diff = SecretAuth(("diff_key", "diff_pass"))

        # Equality comparisons
        assert auth1 == auth2
        assert auth1 != auth_diff
        assert auth1 != "invalid_type"
        assert auth1 == ("user_key", "secret_pass")

        # Hash support for dict lookups
        lookup = {auth1: "authenticated"}
        assert lookup[auth2] == "authenticated"

        # Blocked indexing (CWE-316)
        with pytest.raises(TypeError, match="Credential extraction via indexing is blocked"):
            _ = auth1[0]

        # Blocked iteration / tuple unpacking (CWE-316)
        with pytest.raises(TypeError, match="Credential extraction via iteration is blocked"):
            for _ in auth1:
                pass


class TestSecureHTTPAdapter:
    """Test suite covering custom TLS 1.2+ adapter and proxy manager security."""

    def test_secure_http_adapter_proxy_manager(self) -> None:
        """Cover SecureHTTPAdapter.proxy_manager_for TLS configuration."""
        adapter = SecureHTTPAdapter()
        proxy_manager = adapter.proxy_manager_for("http://127.0.0.1:8080")
        assert proxy_manager.connection_pool_kw.get("ssl_context") is not None


class TestAuthCoercionAndValidation:
    """Test suite for robust authentication validation and coercion (CWE-113, CWE-316)."""

    def test_valid_bearer_token(self) -> None:
        """Verify valid string tokens return cleanly as bearer tokens."""
        token = "secret_bearer_token_123"
        result = SecurityGuard.validate_and_coerce_auth(token)
        assert result == token

    def test_invalid_empty_bearer_token(self) -> None:
        """Verify empty or whitespace-only string tokens raise ValueError."""
        with pytest.raises(ValueError, match="Bearer token cannot be an empty string"):
            SecurityGuard.validate_and_coerce_auth("   ")

    def test_bearer_token_crlf_injection(self) -> None:
        """Verify string tokens with control characters raise ValueError."""
        with pytest.raises(ValueError, match="Auth credentials contain forbidden control characters"):
            SecurityGuard.validate_and_coerce_auth("token\rwith\nnewline")

    def test_valid_basic_auth_tuple(self) -> None:
        """Verify valid (key, secret) tuples are successfully coerced into SecretAuth."""
        auth = ("my_api_key", "my_api_secret")
        result = SecurityGuard.validate_and_coerce_auth(auth)
        assert isinstance(result, SecretAuth)
        assert result == auth

    def test_invalid_tuple_length(self) -> None:
        """Verify tuples with incorrect element counts raise ValueError."""
        with pytest.raises(ValueError, match="Basic auth tuple must contain exactly two elements"):
            SecurityGuard.validate_and_coerce_auth(("single_key",))  # type: ignore[arg-type]

    def test_invalid_tuple_types(self) -> None:
        """Verify non-string elements inside basic auth tuples raise TypeError."""
        with pytest.raises(TypeError, match="Auth tuple elements must be strings"):
            SecurityGuard.validate_and_coerce_auth(("key", 123))  # type: ignore[arg-type]

    def test_empty_tuple_elements(self) -> None:
        """Verify empty or whitespace-only strings inside auth tuples raise ValueError."""
        with pytest.raises(ValueError, match="Auth credentials cannot be empty or whitespace-only"):
            SecurityGuard.validate_and_coerce_auth(("", "secret"))

    def test_tuple_crlf_injection(self) -> None:
        """Verify auth tuple elements containing CRLF or control characters raise ValueError."""
        with pytest.raises(ValueError, match="Auth credentials contain forbidden control characters"):
            SecurityGuard.validate_and_coerce_auth(("key", "secret\r"))

    def test_tuple_invalid_unicode_chars(self) -> None:
        """Verify forbidden Unicode space/separator characters (e.g. \\xa0) raise ValueError."""
        with pytest.raises(ValueError, match="Auth credentials contain invalid whitespace or control characters"):
            SecurityGuard.validate_and_coerce_auth(("key", "secret\xa0"))

    def test_none_auth(self) -> None:
        """Verify None auth returns None safely."""
        assert SecurityGuard.validate_and_coerce_auth(None) is None

    def test_invalid_auth_type(self) -> None:
        """Verify unsupported auth types raise TypeError."""
        with pytest.raises(TypeError, match="Invalid auth type"):
            SecurityGuard.validate_and_coerce_auth(12345)  # type: ignore[arg-type]


class TestSecurityGuard:
    """Test suite covering perimeter guardrails, URI sanitization, inputs, and payloads."""

    # -------------------------------------------------------------------------
    # Configuration & URL Validation (SSRF / CWE-918)
    # -------------------------------------------------------------------------
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

    def test_check_request_security_proxy_warning(self) -> None:
        """Cover unencrypted HTTP proxy warning."""
        with pytest.warns(UserWarning, match="Unencrypted HTTP proxy detected"):
            SecurityGuard.check_request_security({"proxies": {"https": "http://insecure-proxy.com:8080"}})

    def test_filter_safe_kwargs(self) -> None:
        """Cover filtering out disallowed client kwargs (CWE-915)."""
        input_kwargs = {"verify": True, "timeout": 10, "disallowed_header_injection": "bad"}
        filtered = SecurityGuard.filter_safe_kwargs(input_kwargs)
        assert "verify" in filtered
        assert "timeout" not in filtered
        assert "disallowed_header_injection" not in filtered

    # -------------------------------------------------------------------------
    # Headers & Control Characters (CWE-113, CWE-20, CWE-117)
    # -------------------------------------------------------------------------
    def test_sanitize_headers_catches_crlf(self) -> None:
        """Coverage: HTTP Header Injection (CWE-113)."""
        with pytest.raises(ValueError, match="CRLF injection"):
            SecurityGuard.sanitize_headers({"X-Custom": "val\r\ninjected"})

    def test_check_control_characters(self) -> None:
        """Coverage: Null byte injection (CWE-20)."""
        with pytest.raises(ValueError, match="Unprintable control character"):
            SecurityGuard.check_control_characters("field", "bad\x00string")

    def test_sanitize_log_trace(self) -> None:
        """Coverage: CWE-117 Log Forging."""
        clean = SecurityGuard.sanitize_log_trace("My\nTrace\rID")
        assert clean == "My_Trace_ID"

    # -------------------------------------------------------------------------
    # Path Segment Sanitization (CWE-22, CWE-94, CWE-79, CWE-116)
    # -------------------------------------------------------------------------
    def test_sanitize_segment_template_injection(self) -> None:
        """Coverage: Block Jinja/Template injection signatures."""
        with pytest.raises(ValueError, match="Template injection attempt"):
            SecurityGuard.sanitize_segment("{{ config.secret }}")

    def test_sanitize_segment_invalid_type(self) -> None:
        """Coverage: Block dicts/lists in path segments."""
        with pytest.raises(TypeError, match="Invalid segment type"):
            SecurityGuard.sanitize_segment({"dict": "not allowed"})  # type: ignore[arg-type]

    def test_sanitize_segment_double_encoding(self) -> None:
        """Coverage: Protects against double-encoded path traversal attacks (CWE-116)."""
        with pytest.raises(ValueError, match="Excessive URL encoding"):
            # Percent encode "%25" three times -> %252525 -> %2525 -> %25
            SecurityGuard.sanitize_segment("%2525252525")

    def test_sanitize_segment_slashes(self) -> None:
        """Coverage: Verify unescaped path traversals in path generation are intercepted."""
        with pytest.raises(ValueError, match="Path traversal attempt"):
            SecurityGuard.sanitize_segment("a/b")
        with pytest.raises(ValueError, match="Path traversal attempt"):
            SecurityGuard.sanitize_segment("a\\b")

    def test_sanitize_segment_xss(self) -> None:
        """Coverage: Prevent URL-based XSS injection via dynamically generated attributes."""
        with pytest.raises(ValueError, match="XSS attempt detected"):
            SecurityGuard.sanitize_segment("<script>")

    # -------------------------------------------------------------------------
    # Attachment Path & File Size Guardrails (CWE-22, CWE-400)
    # -------------------------------------------------------------------------
    def test_validate_attachment_path_traversal(self, tmp_path: Path) -> None:
        """Coverage: Path traversal enforcement (CWE-22)."""
        with pytest.raises(ValueError, match="Traversal detected"):
            SecurityGuard.validate_attachment_path("../../etc/passwd", tmp_path)

    def test_validate_attachment_path_no_sandbox(self) -> None:
        """Coverage: Fallback zero-trust checks for OS roots and path traversal."""
        with pytest.raises(ValueError, match="Path traversal tokens"):
            SecurityGuard.validate_attachment_path("../etc/passwd")

        with pytest.raises(ValueError, match="explicitly forbidden"):
            SecurityGuard.validate_attachment_path("/etc/passwd")

    def test_validate_attachment_path_forbidden_components(self) -> None:
        """Coverage: Block access when crossing OS structural thresholds."""
        with pytest.raises(ValueError, match="explicitly forbidden"):
            SecurityGuard.validate_attachment_path("/a/windows/b.txt")

    def test_check_file_size_exceeded(self, tmp_path: Path) -> None:
        """Coverage: Hits CWE-400 resource exhaustion."""
        test_file = tmp_path / "large.txt"
        test_file.write_bytes(b"0" * 1025)
        with pytest.raises(ValueError, match="exceeds safe threshold"):
            SecurityGuard.check_file_size(test_file, max_size_bytes=1000)

    def test_file_and_attachment_edge_cases(self, tmp_path: Path) -> None:
        """Cover non-regular file checks, tempdir execution, and missing files."""
        # Passing a directory instead of a file to check_file_size
        with pytest.raises(ValueError, match="Path is not a regular file"):
            SecurityGuard.check_file_size(tmp_path)

        # Missing file rejected as non-regular file
        non_existent = tmp_path / "does_not_exist.txt"
        with pytest.raises(ValueError, match="Path is not a regular file"):
            SecurityGuard.check_file_size(non_existent)

        # OS Temporary Directory allowance without sandbox parameter
        with tempfile.NamedTemporaryFile(mode="w+", delete=False) as tf:
            tf.write("content")
            temp_path = Path(tf.name)

        try:
            resolved = SecurityGuard.validate_attachment_path(temp_path)
            assert resolved.exists()
        finally:
            temp_path.unlink(missing_ok=True)

    # -------------------------------------------------------------------------
    # Timeout Validation & Resource Exhaustion (CWE-400)
    # -------------------------------------------------------------------------
    def test_timeout_bounds_and_boolean_guards(self) -> None:
        """Cover timeout bool rejection, >24h limits, OverflowError, and malformed tuples."""
        # Boolean rejection
        with pytest.raises(TypeError, match="Timeout must be a numeric float or int"):
            SecurityGuard.validate_timeout(True)

        # Exceeding 24-hour limit
        with pytest.raises(ValueError, match="exceeds maximum allowed limit"):
            SecurityGuard.validate_timeout(86401.0)

        # Tuple length mismatch
        with pytest.raises(ValueError, match="Timeout tuple must contain exactly two elements"):
            SecurityGuard.validate_timeout((1.0, 2.0, 3.0))  # type: ignore[arg-type]

        # Non-numeric tuple components
        with pytest.raises(TypeError, match="Timeout must be a numeric float or int|Timeout tuple elements must be valid numeric values"):
            SecurityGuard.validate_timeout((1.0, "invalid"))  # type: ignore[arg-type]

    # -------------------------------------------------------------------------
    # Domain Normalization (RFC 3490 / Punycode)
    # -------------------------------------------------------------------------
    def test_normalize_domain_punycode(self) -> None:
        """Coverage: IDN homograph normalization."""
        puny = SecurityGuard.normalize_domain("info@münchen.de")
        assert puny == "info@xn--mnchen-3ya.de"

    def test_normalize_domain_exceptions(self) -> None:
        """Coverage: Ensure homograph IDNA encoder falls back securely on invalid bounds."""
        with pytest.raises(ValueError, match="Invalid IDN in email"):
            SecurityGuard.normalize_domain("user@" + "x" * 1000)

        with pytest.raises(ValueError, match="Invalid IDN"):
            SecurityGuard.normalize_domain("x" * 1000)

    def test_normalize_domain_empty(self) -> None:
        """Cover empty string handling in normalize_domain."""
        assert SecurityGuard.normalize_domain("") == ""

    # -------------------------------------------------------------------------
    # Payload Hashing & Idempotency Fingerprints
    # -------------------------------------------------------------------------
    def test_generate_payload_fingerprint(self) -> None:
        """Coverage: Idempotency hashing mechanism."""
        payload1 = {"a": 1, "b": 2, "CustomID": "ignore"}
        payload2 = {"b": 2, "a": 1, "EventPayload": "ignore"}
        assert SecurityGuard.generate_payload_fingerprint(payload1) == SecurityGuard.generate_payload_fingerprint(
            payload2
        )

    def test_generate_payload_fingerprint_cyclic(self) -> None:
        """Coverage: Prevent recursion errors on cyclic references."""
        cyclic: dict[str, Any] = {}
        cyclic["a"] = cyclic
        assert SecurityGuard.generate_payload_fingerprint(cyclic)

    def test_generate_payload_fingerprint_max_depth(self) -> None:
        """Coverage: Enforce maximum nesting depth limits."""
        deep: Any = {"a": 1}
        for _ in range(55):
            deep = {"a": deep}

        with pytest.raises(ValueError, match="Payload hashing failed due to malformed"):
            SecurityGuard.generate_payload_fingerprint(deep)

    # -------------------------------------------------------------------------
    # HTML Safety & SpamGuard Static Analysis
    # -------------------------------------------------------------------------
    def test_analyze_html_safety_whitespace(self) -> None:
        """Coverage: Immediate return on whitespace strings."""
        assert SecurityGuard.analyze_html_safety("   ")["is_safe"] is True

    def test_analyze_html_safety_blocks_xss(self) -> None:
        """Coverage: SpamGuard catches script tags."""
        with pytest.raises(ValueError, match="executable Javascript/XSS vectors"):
            SecurityGuard.analyze_html_safety("<script>alert(1)</script>")

    def test_analyze_html_safety_blocks_events(self) -> None:
        """Coverage: SpamGuard catches inline events."""
        with pytest.raises(ValueError, match="blocked script/event execution tags"):
            SecurityGuard.analyze_html_safety("<img src='x' onerror='alert(1)'>")

    def test_spam_guard_html_analysis_object_embed(self) -> None:
        """Coverage: Hit the alternate <object> and <embed> branches."""
        with pytest.raises(ValueError, match="Security Violation: HTML contains executable Javascript/XSS vectors."):
            SecurityGuard.analyze_html_safety("<object data='x'></object>")

        with pytest.raises(ValueError, match="Security Violation: HTML contains executable Javascript/XSS vectors."):
            SecurityGuard.analyze_html_safety("<embed src='x'></embed>")

    def test_spam_guard_html_analysis_htmlparser_error(self) -> None:
        """Coverage: Trigger Failsafe on HTMLParser crash."""

        class CrashParser(HTMLParser):
            def feed(self, data: str) -> None:
                raise RecursionError("Simulated crash")

        with patch.object(SecurityGuard, "_SpamGuardParser", CrashParser):
            with pytest.raises(Exception, match="Fatal HTML parsing error"):
                SecurityGuard.analyze_html_safety("<div></div>")

    # -------------------------------------------------------------------------
    # PEP 578 Audit Logging
    # -------------------------------------------------------------------------
    @patch("sys.audit")
    def test_audit_hooks_are_emitted(self, mock_audit: MagicMock) -> None:
        """Coverage: PEP 578 integration."""
        with pytest.raises(ValueError, match="Path traversal attempt"):
            SecurityGuard.sanitize_segment("..")
        mock_audit.assert_called_with("mailjet.security.path_traversal", "..")
