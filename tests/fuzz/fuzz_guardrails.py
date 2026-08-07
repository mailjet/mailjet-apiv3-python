#!/usr/bin/env python3
"""
Fuzz test for Mailjet Core Security Primitives.
Protects against Path Traversal, CRLF Injection, ReDoS, and Type Confusion.
"""

import sys
import atheris

with atheris.instrument_imports():
    from mailjet_rest.utils.guardrails import SecurityGuard

def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 4)

    try:
        if target == 0:
            # Target 1: Path Traversal (CWE-22)
            payload = fdp.ConsumeUnicodeNoSurrogates(256) if fdp.ConsumeBool() else fdp.ConsumeBytes(256)
            SecurityGuard.validate_attachment_path(payload, safe_base_dir="/tmp/safe")

        elif target == 1:
            # Target 2: CRLF Header Injection (CWE-113)
            key = fdp.ConsumeUnicodeNoSurrogates(32)
            val = fdp.ConsumeInt(1000) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(128)
            SecurityGuard.sanitize_headers({key: val})

        elif target == 2:
            # Target 3: Log Forging (CWE-117)
            dangerous_input = fdp.ConsumeUnicodeNoSurrogates(256)
            sanitized = SecurityGuard.sanitize_log_trace(dangerous_input)
            if "\r" in sanitized or "\n" in sanitized:
                raise RuntimeError("Security Failure: Log Sanitizer failed to block CRLF injection.")

        elif target == 3:
            # Target 4: Magic method interception (Deprecated but maintained for safety)
            SecurityGuard.check_request_security({"proxies": {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20)}})

        elif target == 4:
            # Target 5: RFC-9110 Control Character Injection (NEW)
            payload = fdp.ConsumeUnicodeNoSurrogates(256)
            SecurityGuard.check_control_characters("fuzzed_field", payload)

    except (ValueError, TypeError, FileNotFoundError, AttributeError):
        # SECURITY SUCCESS: The fail-closed architecture intercepted the malformed data.
        pass
    except RecursionError:
        raise RuntimeError("CRITICAL SECURITY BUG: Malformed string caused RecursionError!")
    except Exception as e:
        # UNHANDLED CRASH: MemoryError, KeyError, etc.
        raise RuntimeError(f"UNHANDLED CRASH in Security Primitives: {type(e).__name__} - {e}") from e

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
