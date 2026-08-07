#!/usr/bin/env python3
"""
Fuzz test for Config Validation and Routing Dictionary.
Focuses on type confusion, chaotic URLs, and dictionary contract enforcement.
"""
import logging
import sys
from typing import Any

import atheris

from mailjet_rest.errors import ValidationError, MailjetAuthError
from mailjet_rest.config import Config

logging.disable(logging.CRITICAL)

with atheris.instrument_imports():
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
            None
        ]

        config = Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(100) or "https://api.mailjet.com",
            version=fdp.ConsumeUnicodeNoSurrogates(10),
            timeout=fdp.PickValueInList(chaos_types)
        )

        # Fuzz the magic __getitem__ routing logic
        routing_key = fdp.ConsumeUnicodeNoSurrogates(20)

        try:
            url_data, headers = config[routing_key]

            # Strict Contract Enforcements:
            if not isinstance(url_data, (str, dict)):
                raise RuntimeError("CRASH: Config output breached return contract.")

        except KeyError as e:
            # Expected for invalid routing keys.
            # We want to ensure this doesn't crash the wider app if trapped cleanly.
            pass

    except (ValueError, TypeError, ValidationError, MailjetAuthError):
        # We expect Config to reject bad inputs securely
        pass
    except Exception as e:
        raise RuntimeError(f"CRASH: Config failed to handle input securely: {e}") from e

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
