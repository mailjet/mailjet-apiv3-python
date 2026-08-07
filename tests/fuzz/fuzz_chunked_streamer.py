#!/usr/bin/env python3
"""Fuzz test for the ChunkedStreamer file encoding utility.
Targets File I/O boundaries, buffer sizes, and Base64 encoding stability.
"""

import logging
import sys
import tempfile
from pathlib import Path

import atheris


with atheris.instrument_imports():
    from mailjet_rest.builders import ChunkedStreamer

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Create a temporary file to fuzz the File I/O
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        # Write chaotic bytes to test binary-to-base64 boundaries
        tmp.write(fdp.ConsumeBytes(fdp.ConsumeIntInRange(1, 4096)))
        tmp_path = Path(tmp.name)

    try:
        # Fuzz the chunk size to test edge conditions
        # (e.g., 0, negative values, or absurdly large buffers)
        chunk_size = fdp.ConsumeIntInRange(-10, 1000000)

        # The Streamer should either succeed gracefully or throw a predictable ValueError
        # for invalid chunk sizes. It must NOT segfault or cause an OOM Panic.
        encoded_result = ChunkedStreamer.encode_file(tmp_path, chunk_size=chunk_size)

        if not isinstance(encoded_result, str):
            raise RuntimeError("CRASH: ChunkedStreamer returned a non-string object.")

    except (ValueError, OSError):
        # Expected for malformed chunk sizes or OS-level read issues
        pass
    except MemoryError:
        raise RuntimeError("CRASH: ChunkedStreamer caused a MemoryError.")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in ChunkedStreamer: {type(e).__name__} - {e}") from e
    finally:
        # Cleanup temp file to avoid polluting the disk across millions of iterations
        if tmp_path.exists():
            tmp_path.unlink()


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
