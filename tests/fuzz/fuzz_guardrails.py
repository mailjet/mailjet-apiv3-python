import atheris
import sys

from pathlib import Path
from mailjet_rest.utils.guardrails import SecurityGuard

with atheris.instrument_imports():
    pass

def fuzz_log_sanitization(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 1: Log Forging (CWE-117) prevention."""
    # Feed arbitrary bytes to sanitize_log_trace
    dangerous_input = fdp.ConsumeUnicodeNoSurrogates(100)
    # Inside fuzz_log_sanitization
    sanitized = SecurityGuard.sanitize_log_trace(dangerous_input)
    if "\r" in sanitized or "\n" in sanitized:
        raise RuntimeError("Security Failure: Sanitizer failed to block CRLF injection")

def fuzz_path_jailing(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 2: Path Traversal (CWE-22) prevention."""
    # Create a fake file path and a safe base directory
    try:
        path_input = fdp.ConsumeUnicodeNoSurrogates(50)
        # We simulate a "jail" at /tmp/safe
        SecurityGuard.validate_attachment_path(path_input, safe_base_dir="/tmp/safe")
    except (ValueError, FileNotFoundError):
        # Expected: security violation or missing file
        pass

def TestOneInput(data: bytes) -> None:
    if len(data) < 3:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 1)

    if target == 0:
        fuzz_log_sanitization(fdp)
    else:
        fuzz_path_jailing(fdp)

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
