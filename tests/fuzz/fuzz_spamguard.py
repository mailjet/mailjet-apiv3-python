#!/usr/bin/env python3
"""Fuzz test for the Mailjet SpamGuard and HTML static analyzer.
Targets ReDoS, infinite recursion, memory exhaustion bypasses in the HTML parser.
"""

import logging
import sys

import atheris


with atheris.instrument_imports():
    from mailjet_rest.errors import ValidationError
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate chaotic HTML (mix of valid tags, malformed attributes, and binary noise)
    html_content = fdp.ConsumeUnicodeNoSurrogates(1024)

    # Occasionally synthesize a >5MB string to trigger the Resource Exhaustion exception
    if fdp.ConsumeBool():
        html_content = html_content * fdp.ConsumeIntInRange(5000, 6000)

    try:
        report = SecurityGuard.analyze_html_safety(html_content)

        if not isinstance(report, dict):
            raise RuntimeError("CRASH: SpamGuard did not return a dictionary.")
        if "is_safe" not in report or "issues" not in report:
            raise RuntimeError("CRASH: SpamGuard return payload breached contract.")

    except (ValueError, ValidationError):
        # SECURITY SUCCESS: Normal Python rejections for XSS, OOM Limits, or malformed edge cases
        pass
    except RecursionError:
        raise RuntimeError("CRITICAL SECURITY BUG: Malformed HTML caused a RecursionError in _SpamGuardParser!")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in SpamGuard: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
