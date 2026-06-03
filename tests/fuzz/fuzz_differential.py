"""
Differential Fuzzer for Mailjet API v3 vs v3.1

This harness feeds the exact same fuzzed dictionary payload into both the
v3 and v3.1 Send API endpoints. It mocks the outbound HTTP requests to test
the internal SDK serialization, routing, and pre-flight validation logic.

If one API version handles the payload safely but the other suffers an
unhandled Python memory/type panic, the fuzzer flags a discrepancy.
"""

import sys
import json
from unittest.mock import patch, MagicMock

import atheris

with atheris.instrument_imports():
    from mailjet_rest import Client


# Initialize Clients globally to reduce instantiation overhead during fuzzing
client_v3 = Client(auth=("fuzz_key", "fuzz_secret"), version="v3")
client_v31 = Client(auth=("fuzz_key", "fuzz_secret"), version="v3.1")

# Define which errors are considered "Dirty" (SDK crashed)
# versus "Clean" (SDK safely caught the bad input)
DIRTY_ERRORS = (KeyError, TypeError, AttributeError, IndexError, RecursionError)


def TestOneInput(data: bytes) -> None:
    """The Atheris fuzzing entry point."""

    # 1. Transform raw bytes into a Python Dictionary payload
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Consume as a JSON string to simulate API payload generation
        payload_str = fdp.ConsumeUnicodeNoSurrogates(fdp.remaining_bytes())
        payload = json.loads(payload_str)
        if not isinstance(payload, dict):
            return  # We only care about JSON object payloads
    except Exception:
        return  # Ignore generic JSON decoding errors (we are fuzzing the SDK, not the json library)

    # 2. Mock the outbound HTTP connection
    # We want to test the SDK's internal logic, not spam the real Mailjet API
    with patch("requests.Session.request") as mock_request:
        # Setup a dummy successful HTTP response
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"Message": "Fuzzed"}
        mock_request.return_value = mock_response

        # 3. Execute v3 Logic
        v3_exc = None
        try:
            client_v3.send.create(data=payload)
        except Exception as e:
            v3_exc = e

        # 4. Execute v3.1 Logic
        v31_exc = None
        try:
            client_v31.send.create(data=payload)
        except Exception as e:
            v31_exc = e

        # 5. Differential Analysis
        v3_is_dirty = isinstance(v3_exc, DIRTY_ERRORS)
        v31_is_dirty = isinstance(v31_exc, DIRTY_ERRORS)

        if v3_is_dirty != v31_is_dirty:
            # One endpoint crashed violently, the other didn't.
            error_msg = (
                f"\n[!] DIFFERENTIAL VULNERABILITY DETECTED [!]\n"
                f"-------------------------------------------\n"
                f"Payload: {json.dumps(payload)}\n\n"
                f"v3 Output   : {type(v3_exc).__name__ if v3_exc else 'Success'} - {v3_exc}\n"
                f"v3.1 Output : {type(v31_exc).__name__ if v31_exc else 'Success'} - {v31_exc}\n"
                f"-------------------------------------------\n"
            )
            # Raising an AssertionError halts LibFuzzer and saves the crash artifact
            raise AssertionError(error_msg)


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
