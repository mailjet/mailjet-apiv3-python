"""Atheris fuzzing target for the Mailjet SDK."""

import atheris
import sys

# Instrument imports allows Atheris to track code coverage during fuzzing
with atheris.instrument_imports():
    from mailjet_rest.builders import MessageBuilder
    from mailjet_rest.utils.guardrails import SecurityGuard
    from mailjet_rest.errors import MailjetAuthError, ValidationError

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    try:
        # Fuzzing logic
        # 1. Fuzz the Telemetry Sanitizer
        test_trace = fdp.ConsumeUnicodeNoSurrogates(100)
        SecurityGuard.sanitize_log_trace(test_trace)

        # 2. Fuzz the Message Builder
        builder = MessageBuilder()
        builder.set_sender(fdp.ConsumeUnicodeNoSurrogates(50))
        builder.add_recipient(fdp.ConsumeUnicodeNoSurrogates(50))
        builder.set_subject(fdp.ConsumeUnicodeNoSurrogates(100))
        builder.set_content(text=fdp.ConsumeUnicodeNoSurrogates(200))

        # Build the payload
        builder.build()


    except (ValueError, ValidationError, MailjetAuthError):
        # ValueError is an EXPECTED result of bad input (e.g., empty sender).
        # We catch it so the fuzzer knows this is not a crash.
        pass
    except Exception as e:
        # If we hit an unhandled exception (like a TypeError during string manipulation),
        # we raise it so ClusterFuzzLite records a crash.
        raise RuntimeError(f"Fuzzer found an unhandled exception: {e}") from e

def main() -> None:
    # Setup and run the fuzzer
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
