#!/usr/bin/env python3
"""Fuzz test for the Mailjet SpamGuard and HTML static analyzer.

Targets ReDoS, infinite recursion, memory exhaustion bypasses in the HTML
parser.
"""

import logging
import sys
import atheris

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.errors import ValidationError
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)

MAX_HTML_LIMIT = 5 * 1024 * 1024  # 5MB


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Mix structured HTML vectors (tags, event handlers, URIs, entities) with chaotic noise
    # so the fuzzer exercises _SpamGuardParser branches instead of plain-text fast-paths.
    mode = fdp.ConsumeIntInRange(0, 2)
    if mode == 0:
        html_content = fdp.ConsumeUnicodeNoSurrogates(4096)
    elif mode == 1:
        tag = fdp.PickValueInList(["script", "svg", "iframe", "img", "a", "object", "style", "div", "meta"])
        attr = fdp.PickValueInList(["onload", "onerror", "onclick", "href", "src", "style", "data"])
        scheme = fdp.PickValueInList(["javascript:", "vbscript:", "data:text/html,", "https://", "&#x6a;avascript:"])
        payload = fdp.ConsumeUnicodeNoSurrogates(128)
        html_content = f'<{tag} {attr}="{scheme}{payload}">{fdp.ConsumeUnicodeNoSurrogates(128)}</{tag}>'
    else:
        depth = fdp.ConsumeIntInRange(1, 80)
        noise = fdp.ConsumeUnicodeNoSurrogates(32)
        html_content = ("<div>" * depth) + noise + ("</div>" * (depth // 2))

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
        raise RuntimeError("CRITICAL SECURITY BUG: Malformed HTML caused a RecursionError in _SpamGuardParser!")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in SpamGuard: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
