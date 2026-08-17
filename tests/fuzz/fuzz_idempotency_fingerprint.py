#!/usr/bin/env python3
"""Fuzz test for Idempotency Hash Generation and JSON Serialization limits.
Hunts for unhandled circular references and recursive type crashes.
"""

import logging
import sys
from typing import Any

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest.utils.guardrails import SecurityGuard

logging.disable(logging.CRITICAL)


class PoisonedObject:
    """An object designed to crash json.dumps(default=str) by poisoning __str__"""

    def __init__(self, exception_to_raise: Exception):
        self.exception_to_raise = exception_to_raise

    def __str__(self) -> str:
        raise self.exception_to_raise


def generate_chaotic_payload(fdp: atheris.FuzzedDataProvider, depth: int = 0) -> Any:
    """Recursively generates a dictionary capable of crashing native json libraries."""
    if depth > 4:
        return fdp.ConsumeUnicodeNoSurrogates(16)

    choice = fdp.ConsumeIntInRange(0, 5)
    if choice == 0:
        return fdp.ConsumeUnicodeNoSurrogates(32)
    if choice == 1:
        return fdp.ConsumeInt(1000)
    if choice == 2:
        return fdp.ConsumeBytes(16)
    if choice == 3:
        return PoisonedObject(fdp.PickValueInList([ValueError("Poison"), TypeError("Poison")]))
    if choice == 4:
        circ: dict[str, Any] = {}
        circ["self"] = circ
        return circ
    return {fdp.ConsumeUnicodeNoSurrogates(10): generate_chaotic_payload(fdp, depth + 1) for _ in range(2)}


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)
    payload = generate_chaotic_payload(fdp)

    # Randomly wrap the chaotic payload in either a dict or a list to test the new type bounds
    if not isinstance(payload, (dict, list)):
        if fdp.ConsumeBool():
            payload = {"fuzzed_root": payload}
        else:
            payload = [payload, {"fuzzed_root": payload}]

    try:
        _hash = SecurityGuard.generate_payload_fingerprint(payload)
        assert isinstance(_hash, str)
        assert len(_hash) == 64

    except (TypeError, ValueError):
        # Expected validation/fuzzing error; ignore so the fuzzer can continue.  # noqa: S110
        pass
    except RecursionError:
        raise RuntimeError("CRASH: Idempotency Fingerprint hit Infinite Recursion Depth.")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in Fingerprint generation: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
