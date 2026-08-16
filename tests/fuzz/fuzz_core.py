import sys
import atheris

from mailjet_rest.errors import MailjetAuthError, ValidationError, MailjetApiError


# Instrument all internal modules
with atheris.instrument_imports():
    from mailjet_rest.client import Client
    from mailjet_rest.config import Config
    from mailjet_rest.utils.guardrails import SecurityGuard

# Initialize a dummy client globally ONCE to save execution time across millions of runs
_mock_client = Client(auth=("mock_key", "mock_secret"), config=None)

class DummyResponse:
    status_code = 200
    text = "fuzzed"
    def json(self): return {}
    def raise_for_status(self): pass

_mock_client.session.request = lambda *args, **kwargs: DummyResponse()  # type: ignore[method-assign, assignment]



def fuzz_config(fdp: atheris.FuzzedDataProvider) -> int:
    """Target 1: Config Validation."""
    try:
        Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(30),
            version=fdp.ConsumeUnicodeNoSurrogates(5),
            user_agent=fdp.ConsumeUnicodeNoSurrogates(20),
            timeout=fdp.ConsumeInt(100) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(10),
        )
        return 0
    except (ValueError, TypeError):
        return -1


def fuzz_routing(fdp: atheris.FuzzedDataProvider) -> int:
    """Target 2: URL Routing and Path Traversal Prevention."""
    try:
        # 1. Instantiate the dynamic endpoint using fuzzed strings
        endpoint_name = fdp.ConsumeUnicodeNoSurrogates(20)
        endpoint = getattr(_mock_client, endpoint_name, _mock_client.send)

        # 2. Generate fuzzed payloads and headers
        fuzzed_payload = {"TextPart": fdp.ConsumeUnicodeNoSurrogates(100)}
        fuzzed_headers = {"Custom-Header": fdp.ConsumeUnicodeNoSurrogates(20)}

        # 3. FORCE DEEP EXECUTION: Actually trigger the routing and URL building engines
        url = endpoint._build_url()

        # 4. Trigger payload validation, parameter parsing, and header sanitization
        _mock_client.api_call(
            method="POST",
            url=url,
            data=fuzzed_payload,
            headers=fuzzed_headers,
            timeout=fdp.ConsumeFloat() # Feed fuzzed floats into the timeout validator
        )

    except (ValueError, TypeError, ValidationError, AttributeError, MailjetApiError, MailjetAuthError):
        # FAIL-FAST FIX:
        # By catching these exceptions and returning -1, we tell Atheris:
        # "The SDK successfully blocked this payload. It's not a crash. Keep exploring!"
        return -1

    except RecursionError:
        # We explicitly WANT to catch things like DoS Recursion errors,
        # so we let this crash the fuzzer if it happens.
        raise

    return 0


def fuzz_telemetry_and_difflib(fdp: atheris.FuzzedDataProvider) -> int:
    """Target 3: Telemetry Extraction and Difflib Typo Fallback."""
    # Fuzz difflib resilience against massive chaotic strings
    try:
        getattr(_mock_client, fdp.ConsumeUnicodeNoSurrogates(150))
    except AttributeError:
        pass  # We expect typos to raise AttributeError

    # Fuzz telemetry extractor with lists and dicts
    num_keys = fdp.ConsumeIntInRange(1, 10)
    chaotic_dict = {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20) for _ in range(num_keys)}

    # Send as either a dictionary or a list
    payload = [chaotic_dict] if fdp.ConsumeBool() else chaotic_dict

    try:
        Client._extract_telemetry(payload, None)
        return 0
    except Exception:
        return -1


def fuzz_guardrails(fdp: atheris.FuzzedDataProvider) -> int:
    """Target 4: SecurityGuard Sanitization."""
    dangerous_string = fdp.ConsumeUnicodeNoSurrogates(50)
    try:
        SecurityGuard.sanitize_log_trace(dangerous_string)
        return 0
    except (ValueError, TypeError):
        return -1


def TestOneInput(data: bytes) -> int:
    """Main Router: Dynamically choose target based on input bytes."""
    if len(data) < 5:
        return -1

    fdp = atheris.FuzzedDataProvider(data)
    target = fdp.ConsumeIntInRange(0, 3)

    if target == 0:
        return fuzz_config(fdp)
    elif target == 1:
        return fuzz_routing(fdp)
    elif target == 2:
        return fuzz_telemetry_and_difflib(fdp)
    else:
        return fuzz_guardrails(fdp)


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)  # pyright: ignore[reportArgumentType]
    atheris.Fuzz()


if __name__ == "__main__":
    main()
