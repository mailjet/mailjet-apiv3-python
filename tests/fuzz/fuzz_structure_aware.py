#!/usr/bin/env python3
"""Structure-Aware Fuzzer for Semantic Payload Generation.
Tests deeply nested dictionaries, type confusion on schemas, and payload builder limits.
"""

import logging
import sys
from typing import Any

import atheris


with atheris.instrument_imports():
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.errors import ValidationError

logging.disable(logging.CRITICAL)


def _generate_structured_payload(fdp: atheris.FuzzedDataProvider, depth: int = 0) -> dict[str, Any]:
    """Generates a deeply nested, semantically valid dictionary matching Mailjet boundaries."""
    payload: dict[str, Any] = {}

    if depth > 3:  # Guardrail against extreme recursive recursion errors
        return payload

    payload["From"] = {
        "Email": fdp.ConsumeUnicodeNoSurrogates(15) + "@example.com",
        "Name": fdp.ConsumeUnicodeNoSurrogates(15) if fdp.ConsumeBool() else None,
    }

    # Generate chaotic array lengths
    payload["To"] = [
        {"Email": fdp.ConsumeUnicodeNoSurrogates(15) + "@example.com", "Name": fdp.ConsumeUnicodeNoSurrogates(15)}
        for _ in range(fdp.ConsumeIntInRange(1, 3))
    ]

    # Type confusion on expected schemas
    if fdp.ConsumeBool():
        payload["Subject"] = fdp.ConsumeUnicodeNoSurrogates(32)
    else:
        payload["Subject"] = fdp.ConsumeInt(1000)  # Force type rejection

    if fdp.ConsumeBool():
        payload["Variables"] = {fdp.ConsumeUnicodeNoSurrogates(8): _generate_structured_payload(fdp, depth + 1)}

    return payload


def TestOneInput(data: bytes) -> None:
    # Cap size to avoid noisy massive allocations
    if len(data) < 20 or len(data) > 1024:
        return

    fdp = atheris.FuzzedDataProvider(data)

    if fdp.ConsumeBool():
        builder = MessageBuilder()
        try:
            # 1. Structural Fuzzing on the semantic payload engine
            msg = _generate_structured_payload(fdp)

            if "From" in msg and isinstance(msg["From"], dict):
                builder.set_sender(email=msg["From"].get("Email", ""), name=msg["From"].get("Name"))

            if "To" in msg and isinstance(msg["To"], list):
                for recipient in msg["To"]:
                    if isinstance(recipient, dict):
                        builder.add_recipient(email=recipient.get("Email", ""), name=recipient.get("Name"))

            if "Subject" in msg and isinstance(msg["Subject"], str):
                builder.set_subject(msg["Subject"])

            if "Variables" in msg:
                builder._payload["Variables"] = msg["Variables"]

            builder.build()
        except (ValueError, ValidationError, TypeError, AttributeError):
            # Expected for malformed structure or type-confusion checks
            pass
        except RecursionError:
            raise RuntimeError("CRASH: Payload builder hit Infinite Recursion.")
    else:
        t_builder = TemplateContentBuilder()
        try:
            t_builder.set_meta(fdp.ConsumeUnicodeNoSurrogates(10), fdp.ConsumeUnicodeNoSurrogates(10))
            t_builder.set_content(  # type: ignore[call-arg]
                text=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                html=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                mjml=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
            )
            t_builder.build()
        except (ValueError, ValidationError, TypeError, AttributeError):
            pass


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
