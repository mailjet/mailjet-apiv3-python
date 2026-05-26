import atheris
import sys

from mailjet_rest import ValidationError, MailjetAuthError
from mailjet_rest.config import Config

with atheris.instrument_imports():
    pass

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Fuzz the configuration initialization
        Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(100),
            version=fdp.ConsumeUnicodeNoSurrogates(10),
            timeout=fdp.ConsumeInt(100) if fdp.ConsumeBool() else 60.0
        )
    except (ValueError, ValidationError, MailjetAuthError):
        # We expect Config to reject bad inputs; catching this keeps the fuzzer running
        pass
    except Exception as e:
        # If we get a TypeError or other unhandled crash, we want the fuzzer to stop
        raise RuntimeError(f"Config crashed on input: {e}") from e

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
