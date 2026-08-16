"""Property-based tests for Mailjet SDK schemas, routing, and guardrails.
Powered by Hypothesis.
"""

import logging
import math
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.utils.guardrails import RedactingFilter, SecurityGuard


# ==========================================
# 1. Config & Type Confusion Invariants
# ==========================================
@settings(max_examples=500)
@given(
    timeout_val=st.one_of(
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary(),
        st.lists(st.integers()),
        st.tuples(st.floats(allow_nan=True), st.floats()),
        st.none(),
    )
)
def test_property_config_timeout_coercion(timeout_val: Any) -> None:
    """INVARIANT: Config must successfully coerce the timeout into a valid,
    positive float/int (or tuple), leave it as None, or explicitly raise
    a ValueError/TypeError. It must never silently leak bad types.
    """
    import warnings

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        try:
            config = Config(api_url="https://api.mailjet.com/", timeout=timeout_val)

            if config.timeout is None:
                assert True
            elif isinstance(config.timeout, tuple):
                assert len(config.timeout) == 2
                for t in config.timeout:
                    assert isinstance(t, (float, int))
                    if isinstance(t, float):
                        assert not math.isnan(t)
                        assert not math.isinf(t)
                    assert t > 0
            else:
                assert isinstance(config.timeout, (float, int))
                if isinstance(config.timeout, float):
                    assert not math.isnan(config.timeout)
                    assert not math.isinf(config.timeout)
                assert config.timeout > 0
        except (ValueError, TypeError):
            pass


@settings(max_examples=500)
@given(id_val=st.text(), action_id=st.text(alphabet=st.characters(blacklist_categories=("Cs",))))
def test_property_url_traversal_prevention(id_val: Any, action_id: Any) -> None:
    r"""INVARIANT: No matter what malicious string is passed as an ID or Action,
    the resulting URL must never contain unencoded directory traversals.
    """
    try:
        client = Client(auth=("test", "test"), version="v3")
        endpoint = Endpoint(name="contact", client=client)

        url = endpoint._build_url(id_val=id_val, action_id=action_id)

        base_len = len("https://api.mailjet.com/v3/REST/contact")
        suffix = url[base_len:]

        assert "../" not in suffix
        assert "..\\" not in suffix
        assert "\x00" not in suffix
    except ValueError:
        pass


# ==========================================
# 2. Header CRLF Injection Invariants
# ==========================================
@settings(max_examples=500)
@given(headers=st.dictionaries(keys=st.text(min_size=1, max_size=20), values=st.text()))
def test_property_crlf_header_injection(headers: Any) -> None:
    """INVARIANT: If SecurityGuard allows headers to pass, none of the header keys
    or values can contain a Carriage Return (\r) or Line Feed (\n).
    """
    try:
        clean_headers = SecurityGuard.sanitize_headers(headers)
        for key, val in clean_headers.items():
            assert "\r" not in str(key)
            assert "\n" not in str(key)
            assert "\r" not in str(val)
            assert "\n" not in str(val)
    except ValueError as e:
        assert "CRLF" in str(e)


# ==========================================
# 3. Payload Idempotency Hash Invariants
# ==========================================
@settings(max_examples=200)
@given(base_dict=st.dictionaries(st.text(), st.integers()), custom_id=st.text(), event_payload=st.text())
def test_property_idempotency_fingerprint(base_dict: dict, custom_id: str, event_payload: str) -> None:
    """INVARIANT: Hashing must be structurally consistent regardless of dictionary
    key ordering, and must explicitly ignore volatile trace fields.
    """
    payload1 = base_dict.copy()
    payload1["CustomID"] = custom_id
    payload1["EventPayload"] = event_payload

    payload2 = dict(reversed(list(base_dict.items())))
    payload2["CustomID"] = custom_id + "_different"
    payload2["EventPayload"] = event_payload + "_different"

    hash1 = SecurityGuard.generate_payload_fingerprint(payload1)
    hash2 = SecurityGuard.generate_payload_fingerprint(payload2)

    assert hash1 == hash2


# ==========================================
# 4. Message Builder Payload Constraints
# ==========================================
@settings(max_examples=500)
@given(
    email=st.emails(),
    name=st.text(),
    template_id=st.integers(min_value=-1000, max_value=999999999999999),
    custom_id=st.text(max_size=300),
)
def test_property_message_builder_schema(email: str, name: str, template_id: int, custom_id: str) -> None:
    """INVARIANT: The MessageBuilder must successfully map valid data types to the
    SendV31Message schema without raising key errors or internal panics.
    """
    builder = MessageBuilder()
    builder.set_sender(email=email, name=name)
    builder.add_recipient(email=email, name=name)
    builder.set_template(template_id)

    builder._payload["CustomID"] = custom_id

    try:
        result = builder.build()
        assert result["From"]["Email"] == SecurityGuard.normalize_domain(email)
        if name:
            assert result.get("From", {}).get("Name") == name
        assert result.get("TemplateID") == template_id
        assert result.get("CustomID") == custom_id
    except ValueError:
        pass


# ==========================================
# 5. Template Content Builder Invariants
# ==========================================
@settings(max_examples=200)
@given(text_part=st.text(max_size=500), html_part=st.text(max_size=500), mjml_part=st.text(max_size=500))
def test_property_template_builder(text_part: str, html_part: str, mjml_part: str) -> None:
    """INVARIANT: Template builder must correctly assign content blocks and successfully
    generate the payload when at least one block type is passed.
    """
    builder = TemplateContentBuilder()
    builder.set_content(text=text_part, html=html_part, mjml=mjml_part)

    if not any([text_part, html_part, mjml_part]):
        with pytest.warns(PendingDeprecationWarning):
            builder.build()
        return

    payload = builder.build()

    if text_part:
        assert payload["Text-part"] == text_part
    if html_part:
        assert payload["Html-part"] == html_part
    if mjml_part:
        assert payload["MJMLContent"] == mjml_part


# ==========================================
# 6. IDN Normalization
# ==========================================
@settings(max_examples=200)
@given(domain=st.text(min_size=1))
def test_property_idn_normalization(domain: str) -> None:
    """INVARIANT: The IDN normalizer must reliably return a string (punycode) or
    fail-closed with a ValueError. It must not leak UnicodeErrors.
    """
    try:
        result = SecurityGuard.normalize_domain(domain)
        assert isinstance(result, str)
    except ValueError:
        pass


# ==========================================
# 7. Redacting Filter Integrity
# ==========================================
@settings(max_examples=200)
@given(secret=st.text(min_size=5), log_msg=st.text())
def test_property_redacting_filter(secret: str, log_msg: str) -> None:
    """INVARIANT: The RedactingFilter must seamlessly traverse strings and dictionaries
    without raising type or recursion errors.
    """
    record = logging.LogRecord("test", logging.INFO, "fake.py", 1, log_msg, (), None)
    record.args = {"Authorization": f"Bearer {secret}", "nested": [secret, 123]}

    filter_instance = RedactingFilter()
    filter_instance.filter(record)
    assert True
