"""
Property-based tests for granular Mailjet SDK SecurityGuard functions.
Powered by Hypothesis.
"""
from typing import Any
from urllib.parse import urlparse
from pathlib import Path
from hypothesis import given, settings, strategies as st

from mailjet_rest.builders import MessageBuilder
from mailjet_rest.utils.guardrails import SecurityGuard


@settings(max_examples=500)
@given(url=st.text())
def test_property_ssrf_url_validator(url: str) -> None:
    """INVARIANT: The URL validator must reject any scheme other than HTTPS/mailjet.com."""
    try:
        SecurityGuard.validate_config_url(url, "mailjet.com")
        parsed = urlparse(url)
        assert parsed.scheme == "https"
        assert parsed.hostname == "mailjet.com" or str(parsed.hostname).endswith(".mailjet.com")
    except ValueError:
        pass


@settings(max_examples=500)
@given(trace_str=st.text())
def test_property_log_trace_sanitizer(trace_str: str) -> None:
    """INVARIANT: Traces injected into logs must be sanitized into a contiguous block."""
    clean_str = SecurityGuard.sanitize_log_trace(trace_str)
    assert "\r" not in clean_str
    assert "\n" not in clean_str
    assert " " not in clean_str
    assert "\t" not in clean_str


@settings(max_examples=500)
@given(payload=st.text())
def test_property_control_character_rejection(payload: str) -> None:
    """INVARIANT: Must raise ValueError if any non-printable ASCII character is detected."""
    try:
        SecurityGuard.check_control_characters("test_field", payload)
        for char in payload:
            char_code = ord(char)
            if char_code < 32 and char_code != 9:
                raise AssertionError("Control character slipped past validation.")
            assert char_code != 127
    except ValueError:
        pass


@settings(max_examples=400)
@given(
    html_payload=st.text(alphabet=st.characters(blacklist_categories=('Cs',))),
    injection=st.sampled_from(["<script>", "javascript:", "onload=", "<iframe src=''>", "<object data=>"])
)
def test_property_spamguard_xss_detection(html_payload: str, injection: str) -> None:
    """INVARIANT: SpamGuard must safely parse random text and ALWAYS flag exact malicious events/tags."""
    poisoned_payload = html_payload + injection

    try:
        SecurityGuard.analyze_html_safety(html_payload)
    except ValueError:
        pass # Safe random strings hitting memory limits or coincidentally forming tags

    try:
        SecurityGuard.analyze_html_safety(poisoned_payload)
        raise AssertionError("SpamGuard failed to intercept known XSS vector.")
    except ValueError as e:
        assert "Security Violation" in str(e)


@settings(max_examples=300)
@given(segments=st.lists(st.text(alphabet=st.characters(blacklist_categories=('Cs',))), min_size=1, max_size=5))
def test_property_validate_attachment_path_resilience(segments: list[str]) -> None:
    """INVARIANT: Path validation must resolve arbitrary segments, blocking traversal and OS roots."""
    raw_path = "/".join(segments)
    try:
        resolved = SecurityGuard.validate_attachment_path(raw_path)
        assert isinstance(resolved, Path)
    except (ValueError, FileNotFoundError):
        # We expect FileNotFoundError (paths don't exist) or ValueError (traversal/OS boundaries crossed)
        pass


@settings(max_examples=200)
@given(
    base_payload=st.one_of(
        st.dictionaries(st.text(), st.integers()),
        st.lists(st.dictionaries(st.text(), st.integers()), min_size=1)
    )
)
def test_property_idempotency_fingerprint_lists(base_payload: Any) -> None:
    """
    INVARIANT: Hashing must safely generate strings for both dicts and lists,
    ensuring nested structures don't crash the idempotency lock.
    """
    try:
        hash_result = SecurityGuard.generate_payload_fingerprint(base_payload)
        assert isinstance(hash_result, str)
        assert len(hash_result) == 64  # SHA-256 length
    except ValueError:
        pass


@settings(max_examples=100)
@given(
    payload=st.text(min_size=1, max_size=6 * 1024 * 1024)
)
def test_property_html_size_limits(payload: str) -> None:
    """
    INVARIANT: HTML and Text payloads strictly > 5MB must raise a ValueError.
    Payloads <= 5MB must not raise length-based errors.
    """
    builder = MessageBuilder()
    builder.set_sender(email="test@test.com")
    builder.add_recipient(email="test@test.com")
    builder.set_content(html=payload)

    try:
        builder.build()
        assert len(payload.encode("utf-8", errors="ignore")) <= 5 * 1024 * 1024
    except ValueError as e:
        if "exceeds 5MB" in str(e) or "exceeds maximum safe length" in str(e):
            assert len(payload.encode("utf-8", errors="ignore")) > 5 * 1024 * 1024
