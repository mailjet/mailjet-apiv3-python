#!/usr/bin/env python3
"""
Fuzz test for the Log RedactingFilter logic.
Focuses on Recursive Dictionary parsing limits and Type Confusion.
"""

import sys
import logging
from typing import Any
import re

import atheris

with atheris.instrument_imports():
    from mailjet_rest.utils.guardrails import RedactingFilter

logging.disable(logging.CRITICAL)

def generate_deep_dict(fdp: atheris.FuzzedDataProvider, depth: int = 0) -> Any:
    """Recursively generate chaotic types to challenge the redaction crawler."""
    if depth > 4:
        return fdp.ConsumeUnicodeNoSurrogates(16)

    choice = fdp.ConsumeIntInRange(0, 4)
    if choice == 0:
        return fdp.ConsumeUnicodeNoSurrogates(32)
    elif choice == 1:
        return fdp.ConsumeInt(1000)
    elif choice == 2:
        return [generate_deep_dict(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(1, 3))]
    elif choice == 3:
        return {fdp.ConsumeUnicodeNoSurrogates(10): generate_deep_dict(fdp, depth + 1) for _ in range(fdp.ConsumeIntInRange(1, 3))}
    return None

def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    msg = fdp.ConsumeUnicodeNoSurrogates(64)
    args = (generate_deep_dict(fdp),)

    try:
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="fake.py",
            lineno=1,
            msg=msg,
            args=args,
            exc_info=None
        )

        # Target the redaction engine with dynamic secret strings
        filter_instance = RedactingFilter()
        filter_instance.filter(record)

        # Prevent LibFuzzer OOM from massive string allocation requests
        # caused by fuzzed Python format specifiers (e.g., %999999999s).
        if isinstance(record.msg, str) and re.search(r"%[^a-zA-Z%]*[0-9]{4,}", record.msg):
            return

        _ = record.getMessage()

    except (ValueError, TypeError, KeyError, OverflowError):
        # Expected for string interpolation mismatches or invalid type comparisons
        pass
    except RecursionError:
        raise RuntimeError("CRASH: RedactingFilter hit Infinite Recursion Depth.")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in RedactingFilter: {type(e).__name__} - {e}") from e

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
