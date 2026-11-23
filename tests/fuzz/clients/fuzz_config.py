#!/usr/bin/env python3
"""Fuzz test for Config Validation.
Focuses on type confusion and instantiation contract enforcement.
"""

import logging
import sys
from typing import Any

import atheris


logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.config import Config


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    try:
        # Create aggressive type confusion for config parameters
        chaos_types: list[Any] = [
            fdp.ConsumeInt(100),
            fdp.ConsumeFloat(),
            fdp.ConsumeUnicodeNoSurrogates(10),
            fdp.ConsumeBytes(10),
            [],
            None,
        ]

        _ = Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(100) or "https://api.mailjet.com",
            version=fdp.ConsumeUnicodeNoSurrogates(10),
            timeout=fdp.PickValueInList(chaos_types),
            user_agent=fdp.ConsumeUnicodeNoSurrogates(40) or "mailjet-fuzz/1.0",
            dry_run=fdp.ConsumeBool(),
            enable_security_audit=fdp.ConsumeBool(),
            verify=fdp.PickValueInList([True, False, None, fdp.ConsumeUnicodeNoSurrogates(32)]),
            auto_idempotency_mode=fdp.PickValueInList(
                ["fingerprint", "uuid4", "off", fdp.ConsumeUnicodeNoSurrogates(12)]
            ),
            pool_connections=fdp.PickValueInList([1, 10, 0, -1, True, fdp.ConsumeInt(8)]),
            pool_maxsize=fdp.PickValueInList([1, 10, 0, -1, False, fdp.ConsumeInt(8)]),
            warn_unclosed=fdp.PickValueInList([True, False, 1, "yes"]),
            max_retries=fdp.PickValueInList([0, 3, 20, 21, -1, True, fdp.ConsumeInt(8)]),
        )

    except (ValueError, TypeError):
        # We expect Config to reject bad inputs securely
        pass
    except Exception as e:
        raise RuntimeError(f"CRASH: Config failed to handle input securely: {e}") from e


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
