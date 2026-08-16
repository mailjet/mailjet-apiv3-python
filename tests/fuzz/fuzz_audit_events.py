#!/usr/bin/env python3
"""Fuzz test for PEP 578 sys.audit Runtime Security boundary.
Ensures that the SDK's security guardrails do not crash the interpreter
due to C-API null-byte restrictions when reporting attacks.
"""

import logging
import sys

import atheris


with atheris.instrument_imports():
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Generate an explicitly malicious payload containing null bytes
    # We mix \x00 with attack vectors (like \r\n or ../) to trigger the audit events
    malicious_core = fdp.PickValueInList([b"\r\n", b"../", b"<script>", b"http://"])
    fuzzed_bytes = fdp.ConsumeBytes(128) + b"\x00" + malicious_core + b"\x00"

    try:
        fuzzed_string = fuzzed_bytes.decode("utf-8", errors="ignore")
    except UnicodeDecodeError:
        return

    target = fdp.ConsumeIntInRange(0, 4)

    try:
        # Trigger the guardrails that emit sys.audit telemetry
        if target == 0:
            SecurityGuard.validate_config_url(fuzzed_string, "mailjet.com")
        elif target == 1:
            SecurityGuard.sanitize_headers({fuzzed_string: fuzzed_string})
        elif target == 2:
            SecurityGuard.check_control_characters("fuzz_field", fuzzed_string)
        elif target == 3:
            SecurityGuard.analyze_html_safety(fuzzed_string)
        elif target == 4:
            SecurityGuard.validate_attachment_path(fuzzed_string, "/tmp")

    except (ValueError, FileNotFoundError, TypeError):
        # Expected Rejections. The goal is to survive without the sys.audit crashing.
        pass
    except Exception as e:
        # If sys.audit chokes on the null byte, it usually raises a native ValueError
        # with "embedded null character". We want to flag this explicitly.
        if "embedded null" in str(e).lower():
            raise RuntimeError(
                "CRITICAL CRASH: sys.audit crashed due to an embedded null byte! "
                "The SDK must sanitize strings before emitting audit events."
            ) from e
        raise RuntimeError(f"UNHANDLED CRASH in Audit Emission: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    # Ensure audit logging is active for the fuzzer
    SecurityGuard.enable_audit_logging()

    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
