"""Property-based tests for Mailjet SDK Message/Template Builders and ChunkedStreamer.

Powered by Hypothesis.
"""

from __future__ import annotations

import base64
import contextlib
from pathlib import Path
import tempfile

import pytest
from hypothesis import given, settings, strategies as st

from mailjet_rest.builders import ChunkedStreamer, MessageBuilder, TemplateContentBuilder
from mailjet_rest.utils.guardrails import SecurityGuard


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
    with contextlib.suppress(ValueError):
        builder.set_sender(email=email, name=name)
        builder.add_recipient(email=email, name=name)
        builder.set_template(template_id)

        builder._payload["CustomID"] = custom_id

        raw_result = builder.build()
        from_payload = dict(raw_result["From"])
        result = dict(raw_result)
        assert from_payload["Email"] == SecurityGuard.normalize_domain(email)
        if name:
            assert from_payload.get("Name") == name
        assert result.get("TemplateID") == template_id
        assert result.get("CustomID") == custom_id


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

    payload = dict(builder.build())

    if text_part:
        assert payload.get("Text-part") == text_part
    if html_part:
        assert payload.get("Html-part") == html_part
    if mjml_part:
        assert payload.get("MJMLContent") == mjml_part


@settings(max_examples=200)
@given(
    file_data=st.binary(),
    # Test extreme chunk sizes from 1 byte up to 1MB
    chunk_size=st.integers(min_value=1, max_value=1000000),
)
def test_property_lossless_chunked_encoding(file_data: bytes, chunk_size: int) -> None:
    """INVARIANT: The ChunkedStreamer must safely read and base64-encode any binary
    payload, across any arbitrary chunk boundary, completely losslessly.
    Decoding the result must yield the exact original bytes.
    """
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        tmp.write(file_data)
        tmp_path = Path(tmp.name)

    try:
        # 1. Encode the file dynamically using the fuzzed chunk size
        b64_str = ChunkedStreamer.encode_file(tmp_path, chunk_size=chunk_size)

        # 2. Decode the result back to raw bytes
        decoded_data = base64.b64decode(b64_str)

        # 3. Mathematical Proof of Lossless Encoding
        assert decoded_data == file_data

    finally:
        # Clean up disk state
        if tmp_path.exists():
            tmp_path.unlink()
