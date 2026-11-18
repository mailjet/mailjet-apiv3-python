"""Atheris fuzzing target for the Mailjet SDK Builders."""

import sys
import warnings

import atheris


warnings.simplefilter("ignore", UserWarning)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder, TemplateContentBuilder
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
            op = fdp.ConsumeIntInRange(0, 8)
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
            elif op == 5:
                builder.set_list_unsubscribe(
                    unsubscribe_url=fdp.ConsumeUnicodeNoSurrogates(64),
                    mailto_address=fdp.ConsumeUnicodeNoSurrogates(32) if fdp.ConsumeBool() else None,
                    one_click=fdp.ConsumeBool(),
                )
            elif op == 6:
                builder.set_tracking(
                    opens=fdp.PickValueInList(
                        ["enabled", "disabled", "account_default", fdp.ConsumeUnicodeNoSurrogates(8)]
                    ),
                    clicks=fdp.PickValueInList(
                        ["enabled", "disabled", "account_default", fdp.ConsumeUnicodeNoSurrogates(8)]
                    ),
                )
            elif op == 7:
                builder.set_custom_id(fdp.ConsumeUnicodeNoSurrogates(64))
                builder.set_template(
                    template_id=fdp.PickValueInList([12345, 0, -1, True, fdp.ConsumeInt(8)]),
                    language_active=fdp.PickValueInList([True, False, "yes"]),  # type: ignore[arg-type]
                )
            elif op == 8:
                builder.attach_inline(
                    file_path=fdp.ConsumeUnicodeNoSurrogates(16),
                    content_type=fdp.ConsumeUnicodeNoSurrogates(16),
                    content_id=fdp.ConsumeUnicodeNoSurrogates(16),
                )

        msg = builder.build()
        SendPayloadBuilder().add_message(msg).set_sandbox_mode(fdp.ConsumeBool()).build()
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
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
