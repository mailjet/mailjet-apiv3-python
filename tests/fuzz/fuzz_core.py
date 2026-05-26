import atheris
import sys

from mailjet_rest import ValidationError, MailjetAuthError


# Instrument all internal modules
with atheris.instrument_imports():
    from mailjet_rest.client import Client
    from mailjet_rest.config import Config
    from mailjet_rest.endpoint import _route_csv, _route_data
    from mailjet_rest.utils.guardrails import SecurityGuard

def fuzz_config(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 1: Config Validation."""
    try:
        Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(30),
            version=fdp.ConsumeUnicodeNoSurrogates(5),
            user_agent=fdp.ConsumeUnicodeNoSurrogates(20),
            timeout=fdp.ConsumeInt(100) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(10)
        )
    except ValueError:
        # Invalid fuzzed config values are expected; ignore and continue fuzzing.
        pass

def fuzz_routing(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 2: URL Routing and Path Traversal Prevention."""
    base = fdp.ConsumeUnicodeNoSurrogates(10)
    ver = fdp.ConsumeUnicodeNoSurrogates(5)
    parts = [fdp.ConsumeUnicodeNoSurrogates(10)]
    id_val = fdp.ConsumeUnicodeNoSurrogates(10)

    try:
        _route_csv(base, ver, parts, id_val, "action", "name_csvdata")
        # FIX: Added the required 6th argument ("dummy_name") here
        _route_data(base, ver, parts, id_val, "action", "dummy_name")
    except (ValueError, ValidationError, MailjetAuthError):
        # We expect and allow explicit validation rejections (like CWE-22 Path Traversal blocks)
        pass
    except Exception as e:
        # Any other exception (like IndexError or unhandled TypeError) is a genuine crash
        raise RuntimeError(f"Routing crashed on malformed input: {e}") from e

def fuzz_telemetry(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 3: Telemetry Extraction."""
    num_keys = fdp.ConsumeIntInRange(1, 10)
    chaotic_dict = {
        fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20)
        for _ in range(num_keys)
    }
    Client._extract_telemetry(chaotic_dict, None)

def fuzz_guardrails(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 4: SecurityGuard Sanitization."""
    dangerous_string = fdp.ConsumeUnicodeNoSurrogates(50)
    SecurityGuard.sanitize_log_trace(dangerous_string)

def TestOneInput(data: bytes) -> None:
    """Main Router: Dynamically choose target based on input bytes."""
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 3)

    # Route to specific subsystem
    if target == 0:
        fuzz_config(fdp)
    elif target == 1:
        fuzz_routing(fdp)
    elif target == 2:
        fuzz_telemetry(fdp)
    else:
        fuzz_guardrails(fdp)

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
