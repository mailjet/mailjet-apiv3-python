#!/usr/bin/env python3
"""Fuzz test for Config Validation.
Focuses on type confusion and instantiation contract enforcement.
"""

import logging
import sys
from typing import Any

import atheris

from mailjet_rest.config import Config


logging.disable(logging.CRITICAL)

with atheris.instrument_imports(enable_loader_override=False):
    pass


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
        )

    except (ValueError, TypeError):
        # We expect Config to reject bad inputs securely
        pass
    except Exception as e:
        raise RuntimeError(f"CRASH: Config failed to handle input securely: {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
