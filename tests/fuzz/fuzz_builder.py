"""Atheris fuzzing target for the Mailjet SDK Builders."""

import sys

import atheris


with atheris.instrument_imports():
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.errors import ValidationError
    from mailjet_rest.utils.guardrails import SecurityGuard


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
            email=fdp.ConsumeUnicodeNoSurrogates(32),
            name=fdp.ConsumeUnicodeNoSurrogates(32) if fdp.ConsumeBool() else None,
        )

        num_ops = fdp.ConsumeIntInRange(1, 6)
        for _ in range(num_ops):
            op = fdp.ConsumeIntInRange(0, 4)
            if op == 0:
                builder.add_recipient(
                    email=fdp.ConsumeUnicodeNoSurrogates(20),
                    name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                )
            elif op == 1:
                builder.set_subject(fdp.ConsumeUnicodeNoSurrogates(64))
            elif op == 2:
                builder.add_cc(
                    email=fdp.ConsumeUnicodeNoSurrogates(20),
                    name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                )
            elif op == 3:
                builder.add_bcc(
                    email=fdp.ConsumeUnicodeNoSurrogates(20),
                    name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                )
            elif op == 4:
                # Fuzz sizes specifically around the 5MB cutoff limits
                content = fdp.ConsumeUnicodeNoSurrogates(1024)
                if fdp.ConsumeBool():
                    builder.set_content(html=content)
                else:
                    builder.set_content(text=content)

        builder.build()
    except (ValueError, TypeError, ValidationError, AttributeError, KeyError, OSError):
        pass

        # ==========================================
        # BLOCK 2: Template Content Builder
        # ==========================================
    try:
        t_builder = TemplateContentBuilder()
        t_builder.set_meta(author=fdp.ConsumeUnicodeNoSurrogates(20), name=fdp.ConsumeUnicodeNoSurrogates(20))
        t_builder.set_content(  # type: ignore[call-arg]
            text=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            html=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
            mjml=fdp.ConsumeUnicodeNoSurrogates(50) if fdp.ConsumeBool() else None,
        )

        headers = {}
        for _ in range(fdp.ConsumeIntInRange(0, 3)):
            headers[fdp.ConsumeUnicodeNoSurrogates(16)] = fdp.ConsumeUnicodeNoSurrogates(32)
        t_builder.set_headers(headers)

        t_builder.build()

    except (ValueError, TypeError, ValidationError, AttributeError, KeyError, OSError):
        pass
    except RecursionError:
        raise RuntimeError("CRASH: Builder JSON Serialization hit Recursion Depth limit.")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in Builder execution: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
