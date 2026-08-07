#!/usr/bin/env python3
"""
Fuzz test for Cryptographic and Edge-Case Guardrails in Mailjet.
Focuses on IDNA Parsing (CWE-176) and Input Validation Type Confusion.
"""

import sys
import logging
from typing import Any

import atheris

with atheris.instrument_imports():
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)


def _get_fuzzed_type(fdp: atheris.FuzzedDataProvider) -> Any:
    """Generate random types to test strict type enforcement."""
    choice = fdp.ConsumeIntInRange(0, 3)
    if choice == 0:
        return fdp.ConsumeUnicodeNoSurrogates(64)
    if choice == 1:
        return fdp.ConsumeInt(10000)
    if choice == 2:
        return None
    return fdp.ConsumeBytes(32)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 2)

    try:
        if target == 0:
            # Target 1: Internationalized Domain Names (IDN) to Punycode (CWE-176)
            # Mix valid structures with surrogate halves and massive lengths
            email_or_domain = fdp.ConsumeUnicodeNoSurrogates(512) if fdp.ConsumeBool() else None
            SecurityGuard.normalize_domain(email_or_domain)  # type: ignore[arg-type]

        elif target == 1:
            # Target 2: Deep SSRF / URL Guard (CWE-918)
            fuzzed_url = fdp.ConsumeUnicodeNoSurrogates(256)
            # Mailjet's config allows specific domains
            SecurityGuard.validate_config_url(fuzzed_url, allowed_root_domain="mailjet.com")

        elif target == 2:
            # Target 3: Integer/Float Timeout Bounds (CWE-400)
            timeout_val: Any
            if fdp.ConsumeBool():
                timeout_val = fdp.ConsumeFloat()
            elif fdp.ConsumeBool():
                timeout_val = fdp.ConsumeInt(10000)
            else:
                timeout_val = (fdp.ConsumeFloat(), fdp.ConsumeFloat())

            SecurityGuard.validate_timeout(timeout_val)

    except UnicodeError as e:
        # A leaked UnicodeError means the normalize_domain fallback failed
        raise RuntimeError(f"CRASH: Leaked UnicodeError during IDNA parsing: {e}") from e
    except (ValueError, TypeError):
        # SECURITY SUCCESS: The Guardrails cleanly rejected malformed/illegal structures
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
