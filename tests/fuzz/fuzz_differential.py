#!/usr/bin/env python3
"""
Differential Fuzzer for Mailjet API v3 vs v3.1 using Semantic Payloads.
This harness feeds the exact same chaotic, deeply nested dictionary into both
versions to ensure the serializers crash/succeed symmetrically.
"""

import json
import sys
from typing import Any
from unittest.mock import MagicMock

import atheris

with atheris.instrument_imports():
    from mailjet_rest import Client

# Initialize Clients globally to reduce instantiation overhead
client_v3 = Client(auth=("fuzz_key", "fuzz_secret"), version="v3")
client_v31 = Client(auth=("fuzz_key", "fuzz_secret"), version="v3.1")

# Define which errors are considered "Dirty" (SDK crashed) vs "Clean" (Safely blocked)
DIRTY_ERRORS = (KeyError, AttributeError, IndexError, RecursionError)

def dumb_mock_request(*args: Any, **kwargs: Any) -> MagicMock:
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = {"Message": "Fuzzed"}
    mock_resp.raise_for_status = MagicMock()
    return mock_resp

client_v3.session.request = dumb_mock_request  # type: ignore[method-assign]
client_v31.session.request = dumb_mock_request  # type: ignore[method-assign]


def _generate_structured_payload(fdp: atheris.FuzzedDataProvider) -> dict[str, Any]:
    """Generates a deeply nested, semantically chaotic dictionary."""
    payload: dict[str, Any] = {}

    # 1. Base boundaries
    payload["FromEmail"] = fdp.ConsumeUnicodeNoSurrogates(32)
    payload["Subject"] = fdp.ConsumeUnicodeNoSurrogates(64)

    # 2. Type confusion on structural components
    choice = fdp.ConsumeIntInRange(0, 3)
    if choice == 0:
        payload["Recipients"] = [{"Email": fdp.ConsumeUnicodeNoSurrogates(16)}]
    elif choice == 1:
        payload["Recipients"] = fdp.ConsumeInt(1000) # Force type validation failure
    elif choice == 2:
        payload["Recipients"] = None

    # 3. Deeply Nested Structures (Recursion limits & Memory)
    if fdp.ConsumeBool():
        nested_vars = {}
        for _ in range(fdp.ConsumeIntInRange(1, 5)):
            nested_vars[fdp.ConsumeUnicodeNoSurrogates(8)] = fdp.ConsumeUnicodeNoSurrogates(16)
        payload["Vars"] = nested_vars

    return payload


def TestOneInput(data: bytes) -> None:
    if len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)
    semantic_payload = _generate_structured_payload(fdp)

    # Execute v3 Logic
    v3_exc = None
    try:
        client_v3.send.create(data=semantic_payload)
    except Exception as e:
        v3_exc = e

    # Execute v3.1 Logic
    v31_exc = None
    try:
        # Wrap payload into v3.1 structure manually
        v31_payload = {"Messages": [semantic_payload]}
        client_v31.send.create(data=v31_payload)
    except Exception as e:
        v31_exc = e

    # Differential Analysis
    v3_is_dirty = isinstance(v3_exc, DIRTY_ERRORS)
    v31_is_dirty = isinstance(v31_exc, DIRTY_ERRORS)

    if v3_is_dirty != v31_is_dirty:
        raise AssertionError(
            f"\n[!] DIFFERENTIAL VULNERABILITY DETECTED [!]\n"
            f"Payload: {json.dumps(semantic_payload)}\n"
            f"v3 Output   : {type(v3_exc).__name__ if v3_exc else 'Success'} - {v3_exc}\n"
            f"v3.1 Output : {type(v31_exc).__name__ if v31_exc else 'Success'} - {v31_exc}\n"
        )

    if isinstance(v3_exc, RecursionError) or isinstance(v31_exc, RecursionError):
        raise RuntimeError("CRASH: Payload processing caused infinite recursion limit breach.")

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
