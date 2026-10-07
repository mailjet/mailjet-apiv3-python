#!/usr/bin/env python3
"""Fuzz test for the Mailjet SpamGuard and HTML static analyzer.

Targets ReDoS, infinite recursion, memory exhaustion bypasses in the HTML
parser.
"""

import logging
import sys
import atheris

with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest.errors import ValidationError
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)

MAX_HTML_LIMIT = 5 * 1024 * 1024  # 5MB


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate chaotic HTML (tags, malformed attributes, binary noise)
    # Limit base size to 4096 chars to keep per-iteration execution speed high
    html_content = fdp.ConsumeUnicodeNoSurrogates(4096)

    # Truly occasionally (1% of runs) verify the >5MB Resource Exhaustion rejection.
    # Guarantee it exceeds 5MB directly so it triggers the O(1) length check instantly.
    if fdp.ConsumeIntInRange(1, 100) == 1:
        html_content = html_content + ("A" * (MAX_HTML_LIMIT + 1024))

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
        raise RuntimeError(
            "CRITICAL SECURITY BUG: Malformed HTML caused a RecursionError in"
            " _SpamGuardParser!"
        )
    except Exception as e:
        raise RuntimeError(
            f"UNHANDLED CRASH in SpamGuard: {type(e).__name__} - {e}"
        ) from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
