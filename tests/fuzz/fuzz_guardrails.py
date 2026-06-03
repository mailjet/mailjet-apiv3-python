import atheris
import sys
import logging

from mailjet_rest.utils.guardrails import SecurityGuard

with atheris.instrument_imports():
    pass

def fuzz_log_sanitization(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 1: Log Forging (CWE-117) prevention."""
    dangerous_input = fdp.ConsumeUnicodeNoSurrogates(100)
    sanitized = SecurityGuard.sanitize_log_trace(dangerous_input)
    if "\r" in sanitized or "\n" in sanitized:
        raise RuntimeError("Security Failure: Sanitizer failed to block CRLF injection")

def fuzz_path_jailing(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 2: Path Traversal (CWE-22) prevention."""
    try:
        path_input = fdp.ConsumeUnicodeNoSurrogates(50)
        SecurityGuard.validate_attachment_path(path_input, safe_base_dir="/tmp/safe")
    except (ValueError, FileNotFoundError):
        pass

def fuzz_crlf_headers(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 3: CRLF Injection in Dictionary values."""
    try:
        fuzzed_dict = {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(30)}
        SecurityGuard.validate_crlf_headers(fuzzed_dict)
    except ValueError:
        # Expected for malformed fuzzed header values; keep fuzzing without failing this case.
        pass

def fuzz_attribute_access(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 4: Magic method interception."""
    try:
        SecurityGuard.validate_attribute_access(
            class_name=fdp.ConsumeUnicodeNoSurrogates(15),
            name=fdp.ConsumeUnicodeNoSurrogates(15)
        )
    except AttributeError:
        pass

def TestOneInput(data: bytes) -> None:
    if len(data) < 3:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 3)

    if target == 0:
        fuzz_log_sanitization(fdp)
    elif target == 1:
        fuzz_path_jailing(fdp)
    elif target == 2:
        fuzz_crlf_headers(fdp)
    else:
        fuzz_attribute_access(fdp)

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    # MUTE THE SDK LOGGING to prevent I/O console bottlenecks
    # and let the fuzzer run at maximum CPU speed.
    logging.disable(logging.CRITICAL)

    atheris.Fuzz()
