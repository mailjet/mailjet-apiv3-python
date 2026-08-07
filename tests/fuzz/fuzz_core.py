import sys

import atheris

from mailjet_rest import MailjetAuthError, ValidationError


# Instrument all internal modules
with atheris.instrument_imports():
    from mailjet_rest.client import Client
    from mailjet_rest.config import Config
    from mailjet_rest.endpoint import Endpoint
    from mailjet_rest.utils.guardrails import SecurityGuard


def fuzz_config(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 1: Config Validation."""
    try:
        Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(30),
            version=fdp.ConsumeUnicodeNoSurrogates(5),
            user_agent=fdp.ConsumeUnicodeNoSurrogates(20),
            timeout=fdp.ConsumeInt(100) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(10),
        )
    except (ValueError, TypeError):
        pass


def fuzz_routing(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 2: URL Routing and Path Traversal Prevention."""
    name = fdp.ConsumeUnicodeNoSurrogates(20)
    id_val = fdp.ConsumeUnicodeNoSurrogates(10) if fdp.ConsumeBool() else None
    action_id = fdp.ConsumeUnicodeNoSurrogates(10) if fdp.ConsumeBool() else None

    class DummyConfig:
        version = "v3"
        api_url = "https://api.mailjet.com/"

    class DummyClient:
        config = DummyConfig()

    try:
        ep = Endpoint(DummyClient(), name)  # type: ignore[arg-type]
        ep._build_url(id_val=id_val, action_id=action_id)
    except (ValueError, ValidationError, MailjetAuthError):
        pass
    except Exception as e:
        raise RuntimeError(f"Routing crashed on malformed input: {e}") from e


def fuzz_telemetry_and_difflib(fdp: atheris.FuzzedDataProvider) -> None:
    """Target 3: Telemetry Extraction and Difflib Typo Fallback."""
    # Fuzz difflib resilience against massive chaotic strings
    client = Client(auth=("test", "test"), version="v3")
    try:
        getattr(client, fdp.ConsumeUnicodeNoSurrogates(150))
    except AttributeError:
        pass

    # Fuzz telemetry extractor with lists and dicts
    num_keys = fdp.ConsumeIntInRange(1, 10)
    chaotic_dict = {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20) for _ in range(num_keys)}

    # Send as either a dictionary or a list
    payload = [chaotic_dict] if fdp.ConsumeBool() else chaotic_dict
    Client._extract_telemetry(payload, None)


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

    if target == 0:
        fuzz_config(fdp)
    elif target == 1:
        fuzz_routing(fdp)
    elif target == 2:
        fuzz_telemetry_and_difflib(fdp)
    else:
        fuzz_guardrails(fdp)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
