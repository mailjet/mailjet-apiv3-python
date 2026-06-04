"""Atheris fuzzing target for the Mailjet SDK Builders."""

import atheris
import sys
from unittest.mock import patch, MagicMock


with atheris.instrument_imports():
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.utils.guardrails import SecurityGuard
    from mailjet_rest.errors import ValidationError

def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return
    fdp = atheris.FuzzedDataProvider(data)

    # ==========================================
    # BLOCK 1: Telemetry Sanitizer
    # ==========================================
    try:
        test_trace = fdp.ConsumeUnicodeNoSurrogates(100)
        SecurityGuard.sanitize_log_trace(test_trace)
    except (ValueError, TypeError, ValidationError, AttributeError):
        # Expected under fuzzed/random inputs; ignore to continue fuzzing.
        pass

    # ==========================================
    # BLOCK 2: Message Builder
    # ==========================================
    try:
        builder = MessageBuilder()
        builder.set_sender(
            email=fdp.ConsumeUnicodeNoSurrogates(20),
            name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None
        )

        for _ in range(fdp.ConsumeIntInRange(1, 3)):
            builder.add_recipient(
                email=fdp.ConsumeUnicodeNoSurrogates(20),
                name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None
            )

        for _ in range(fdp.ConsumeIntInRange(0, 2)):
            builder.add_cc(
                email=fdp.ConsumeUnicodeNoSurrogates(20),
                name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None
            )

        for _ in range(fdp.ConsumeIntInRange(0, 2)):
            builder.add_bcc(
                email=fdp.ConsumeUnicodeNoSurrogates(20),
                name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None
            )

        builder.set_subject(fdp.ConsumeUnicodeNoSurrogates(50))
        builder.set_content(
            text=fdp.ConsumeUnicodeNoSurrogates(100) if fdp.ConsumeBool() else None,
            html=fdp.ConsumeUnicodeNoSurrogates(100) if fdp.ConsumeBool() else None,
        )

        builder.set_template(fdp.ConsumeInt(10000))

        # Fuzz mocked file ingestion
        virtual_file_name = fdp.ConsumeUnicodeNoSurrogates(15)
        virtual_file_data = fdp.ConsumeBytes(100)

        with patch("pathlib.Path.is_file", return_value=True), \
             patch("pathlib.Path.stat", return_value=MagicMock(st_size=len(virtual_file_data))), \
             patch("pathlib.Path.read_bytes", return_value=virtual_file_data):

            if fdp.ConsumeBool():
                builder.attach_file(virtual_file_name)
            if fdp.ConsumeBool():
                builder.attach_inline_image(virtual_file_name)  # type: ignore[attr-defined]

        builder.build()
    except (ValueError, TypeError, ValidationError, AttributeError, KeyError, OSError):
        # Expected under fuzzed/random inputs; ignore to continue fuzzing.
        pass

    # ==========================================
    # BLOCK 3: Template Content Builder
    # ==========================================
    try:
        t_builder = TemplateContentBuilder()
        t_builder.set_meta(
            author=fdp.ConsumeUnicodeNoSurrogates(20),
            name=fdp.ConsumeUnicodeNoSurrogates(20)
        )
        t_builder.set_content(  # type: ignore[call-arg]
            text=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            html=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            mjml=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None  # pyright: ignore[reportCallIssue]
        )

        headers = {}
        for _ in range(fdp.ConsumeIntInRange(0, 2)):
            headers[fdp.ConsumeUnicodeNoSurrogates(10)] = fdp.ConsumeUnicodeNoSurrogates(10)
        t_builder.set_headers(headers)

        t_builder.build()
    except (ValueError, TypeError, ValidationError, AttributeError, KeyError, OSError):
        # Expected for malformed fuzz inputs; keep fuzzing instead of failing the harness.
        pass

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
