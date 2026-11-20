#!/usr/bin/env python3
"""Fuzz test for Mailjet Core Security Primitives.

Protects against Path Traversal, CRLF Injection, ReDoS, Type Confusion,
control-character smuggling, XSS/tag bombs, and mass assignment.
"""

from __future__ import annotations

import sys
from typing import TYPE_CHECKING

import atheris


if TYPE_CHECKING:
    from collections.abc import Callable


with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.errors import ValidationError
    from mailjet_rest.utils.guardrails import SecurityGuard


def _fuzz_attachment_path(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 0: Path Traversal (CWE-22)."""
    payload = fdp.ConsumeUnicodeNoSurrogates(256) if fdp.ConsumeBool() else fdp.ConsumeBytes(256)
    SecurityGuard.validate_attachment_path(payload, safe_base_dir="/tmp/safe")


def _fuzz_sanitize_headers(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 1: CRLF Header Injection (CWE-113)."""
    key = fdp.ConsumeUnicodeNoSurrogates(32)
    val = str(fdp.ConsumeInt(1000)) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(128)
    SecurityGuard.sanitize_headers({key: val})


def _fuzz_sanitize_log_trace(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 2: Log Forging (CWE-117)."""
    dangerous_input = fdp.ConsumeUnicodeNoSurrogates(256)
    sanitized = SecurityGuard.sanitize_log_trace(dangerous_input)
    if "\r" in sanitized or "\n" in sanitized:
        msg = "Security Failure: Log Sanitizer failed to block CRLF injection."
        raise RuntimeError(msg)


def _fuzz_check_request_security(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 3: Proxy/transport request inspection."""
    SecurityGuard.check_request_security(
        {"proxies": {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20)}}
    )


def _fuzz_control_characters(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 4: RFC-9110 Control Character Injection (CWE-20)."""
    payload = fdp.ConsumeUnicodeNoSurrogates(256)
    SecurityGuard.check_control_characters("fuzzed_field", payload)


def _fuzz_validate_and_coerce_auth(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 5: Auth coercion (Tuple vs String Token vs Malformed)."""
    auth_val: str | tuple[str, str] = (
        fdp.ConsumeUnicodeNoSurrogates(128)
        if fdp.ConsumeBool()
        else (
            fdp.ConsumeUnicodeNoSurrogates(32),
            fdp.ConsumeUnicodeNoSurrogates(32),
        )
    )
    SecurityGuard.validate_and_coerce_auth(auth_val)


def _fuzz_analyze_html_safety(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 6: HTML SpamGuard static parser."""
    html = fdp.ConsumeUnicodeNoSurrogates(512)
    SecurityGuard.analyze_html_safety(html)


def _fuzz_filter_safe_kwargs(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 7: Safe Kwargs Filtering (Mass Assignment / CWE-915)."""
    k = fdp.ConsumeUnicodeNoSurrogates(16)
    v = fdp.ConsumeUnicodeNoSurrogates(16)
    SecurityGuard.filter_safe_kwargs({k: v})


_TARGETS: tuple[Callable[[atheris.FuzzedDataProvider], None], ...] = (
    _fuzz_attachment_path,
    _fuzz_sanitize_headers,
    _fuzz_sanitize_log_trace,
    _fuzz_check_request_security,
    _fuzz_control_characters,
    _fuzz_validate_and_coerce_auth,
    _fuzz_analyze_html_safety,
    _fuzz_filter_safe_kwargs,
)


def TestOneInput(data: bytes) -> None:
    """Dispatch fuzz input across all 8 SecurityGuard primitives."""
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = _TARGETS[fdp.ConsumeIntInRange(0, len(_TARGETS) - 1)]

    try:
        target(fdp)
    except (ValueError, TypeError, FileNotFoundError, AttributeError, ValidationError):
        # Expected fail-closed rejection on malformed fuzz input.
        pass
    except RecursionError as exc:
        msg = "CRITICAL SECURITY BUG: Malformed string caused RecursionError!"
        raise RuntimeError(msg) from exc
    except Exception as exc:
        msg = f"UNHANDLED CRASH in Security Primitives: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
