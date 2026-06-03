"""
Property-based tests for Mailjet SDK schemas, routing, and guardrails.
Powered by Hypothesis.
"""

import math
from typing import Any
from hypothesis import given, settings, strategies as st

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.builders import MessageBuilder
from mailjet_rest.utils.guardrails import SecurityGuard


# ==========================================
# 1. Config & Type Confusion Invariants
# ==========================================
@settings(max_examples=500)
@given(
    # Generate extreme floats, massive ints, unicode, bytes, tuples, and None
    timeout_val=st.one_of(
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary(),
        st.lists(st.integers()),
        st.tuples(st.floats(allow_nan=True), st.floats()),
        st.none()
    )
)
def test_property_config_timeout_coercion(timeout_val: Any) -> None:
    """
    INVARIANT: Config must successfully coerce the timeout into a valid,
    positive float (or tuple of floats), leave it as None, or explicitly
    raise a ValueError/TypeError. It must never silently leak bad types.
    """
    try:
        config = Config(api_url="https://api.mailjet.com/", timeout=timeout_val)

        # If instantiation succeeds, the following invariants MUST be true.
        if config.timeout is None:
            assert True
        elif isinstance(config.timeout, tuple):
            assert len(config.timeout) == 2
            for t in config.timeout:
                assert isinstance(t, float)
                assert not math.isnan(t)
                assert not math.isinf(t)
                assert t > 0
        else:
            # It must be perfectly coerced into a standard Python float
            assert isinstance(config.timeout, float)
            assert not math.isnan(config.timeout)
            assert not math.isinf(config.timeout)
            assert config.timeout > 0
    except (ValueError, TypeError):
        # We expect the SDK to safely reject un-parsable types
        pass

@settings(max_examples=500)
@given(
    id_val=st.text(),
    # Use st.characters with blacklist_categories to exclude surrogate chars ('Cs')
    action_id=st.text(alphabet=st.characters(blacklist_categories=('Cs',)))
)
def test_property_url_traversal_prevention(id_val: Any, action_id: Any) -> None:
    r"""
    INVARIANT: No matter what malicious string is passed as an ID or Action,
    the resulting URL must never contain unencoded directory traversals
    (../ or ..\) that could escape the REST API boundary.
    """
    client = Client(auth=("test", "test"), version="v3")
    endpoint = Endpoint(name="contact", client=client)

    url = endpoint._build_url(id_val=id_val, action_id=action_id)

    base_len = len("https://api.mailjet.com/v3/REST/contact")
    suffix = url[base_len:]

    # Invariant checks:
    assert "../" not in suffix
    assert "..\\" not in suffix

    # We check for the RAW null byte.
    # If the SDK safely encodes it to "%00", that is successful mitigation!
    assert "\x00" not in suffix


# ==========================================
# 3. Header CRLF Injection Invariants
# ==========================================
@settings(max_examples=500)
@given(
    headers=st.dictionaries(
        keys=st.text(min_size=1, max_size=20),
        values=st.text()
    )
)
def test_property_crlf_header_injection(headers: Any) -> None:
    """
    INVARIANT: If SecurityGuard allows headers to pass, none of the header values
    can contain a Carriage Return (\\r) or Line Feed (\\n).
    """
    try:
        SecurityGuard.validate_crlf_headers(headers)
        # If validation passed, verify the invariant mathematically
        for val in headers.values():
            val_str = str(val)
            assert "\r" not in val_str
            assert "\n" not in val_str
    except ValueError as e:
        # If it failed, it must be because a CRLF was detected
        assert "CRLF" in str(e)


# ==========================================
# 4. Message Builder Payload Constraints
# ==========================================
@settings(max_examples=500)
@given(
    email=st.emails(),
    name=st.text(),
    template_id=st.integers(min_value=-1000, max_value=999999999999999), # Test massive out-of-bounds DB IDs
    custom_id=st.text(max_size=300)
)
def test_property_message_builder_schema(email: str, name: str, template_id: int, custom_id: str) -> None:
    """
    INVARIANT: The MessageBuilder must successfully map valid data types to the
    SendV31Message schema without raising key errors or internal panics.
    """
    builder = MessageBuilder()
    builder.set_sender(email=email, name=name)
    builder.add_recipient(email=email, name=name)
    builder.set_template(template_id)

    # Access private dict directly to simulate custom property injection
    builder._msg["CustomID"] = custom_id

    try:
        result = builder.build()
        assert result["From"]["Email"] == email
        if name:
            assert result.get("From", {}).get("Name") == name  # pyright: ignore[reportTypedDictNotRequiredAccess]
        assert result.get("TemplateID") == template_id  # pyright: ignore[reportTypedDictNotRequiredAccess]
        assert result.get("CustomID") == custom_id  # pyright: ignore[reportTypedDictNotRequiredAccess]
    except ValueError:
        # Build throws ValueError if missing Text/HTML/Template boundaries, which is safe.
        pass
