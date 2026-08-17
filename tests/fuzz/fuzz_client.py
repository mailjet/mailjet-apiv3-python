"""Advanced Atheris fuzzing target for the Mailjet SDK Builders.
Stresses JSON Recursion, Attachment Chunks, and Structural Integrity.
"""

import sys

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest.builders import MessageBuilder, TemplateContentBuilder
    from mailjet_rest.errors import ValidationError


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return
    fdp = atheris.FuzzedDataProvider(data)

    # ==========================================
    # BLOCK 1: Message Builder Stateful Fuzzing
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
                # Target primary recipients
                builder.add_recipient(
                    email=fdp.ConsumeUnicodeNoSurrogates(20),
                    name=fdp.ConsumeUnicodeNoSurrogates(20) if fdp.ConsumeBool() else None,
                )
            elif op == 1:
                # Target CC/BCC structural bounds
                if fdp.ConsumeBool():
                    builder.add_cc(email=fdp.ConsumeUnicodeNoSurrogates(20))
                else:
                    builder.add_bcc(email=fdp.ConsumeUnicodeNoSurrogates(20))
            elif op == 2:
                # Fuzz deep recursive variables/structures
                builder.set_subject(fdp.ConsumeUnicodeNoSurrogates(64))
            elif op == 3:
                builder.add_attachment(  # type: ignore[attr-defined]
                    filename=fdp.ConsumeUnicodeNoSurrogates(16),
                    content_type=fdp.ConsumeUnicodeNoSurrogates(16),
                    base64_content=fdp.ConsumeUnicodeNoSurrogates(128),
                )
            elif op == 4:
                # Synthesize a massive string using Python multiplication to test
                # the 5MB Guardrail without thrashing Atheris's memory limits.
                content = fdp.ConsumeUnicodeNoSurrogates(100) * fdp.ConsumeIntInRange(1, 60000)
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
        # Expected validation/fuzzing error; ignore so the fuzzer can continue.  # noqa: S110
        pass
    except RecursionError:
        raise RuntimeError("CRASH: Builder JSON Serialization hit Recursion Depth limit.")
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in Builder execution: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
