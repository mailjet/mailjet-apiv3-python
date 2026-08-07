"""
Property-based tests for Mailjet SDK I/O and File Streaming.
Powered by Hypothesis.
"""

import base64
import tempfile
from pathlib import Path

from hypothesis import given, settings, strategies as st

from mailjet_rest.builders import ChunkedStreamer


@settings(max_examples=200)
@given(
    file_data=st.binary(),
    # Test extreme chunk sizes from 1 byte up to 1MB
    chunk_size=st.integers(min_value=1, max_value=1000000)
)
def test_property_lossless_chunked_encoding(file_data: bytes, chunk_size: int) -> None:
    """
    INVARIANT: The ChunkedStreamer must safely read and base64-encode any binary
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
