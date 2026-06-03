import atheris
import sys

from mailjet_rest import ValidationError, MailjetAuthError
from mailjet_rest.config import Config

with atheris.instrument_imports():
    pass

def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return
    fdp = atheris.FuzzedDataProvider(data)
    try:
        # Create aggressive type confusion
        chaos_types = [
            fdp.ConsumeInt(100),               # Valid Int
            fdp.ConsumeFloat(),                # Valid Float
            fdp.ConsumeUnicodeNoSurrogates(10),# Invalid String
            fdp.ConsumeBytes(10),              # Invalid Bytes
            [],                                # Invalid List
            None                               # Invalid None
        ]

        config = Config(
            api_url=fdp.ConsumeUnicodeNoSurrogates(100),
            version=fdp.ConsumeUnicodeNoSurrogates(10),
            timeout=fdp.PickValueInList(chaos_types)
        )

        # Fuzz the magic __getitem__ routing logic
        routing_key = fdp.ConsumeUnicodeNoSurrogates(20)
        _url, _headers = config[routing_key]

    except (ValueError, TypeError, ValidationError, MailjetAuthError):
        # We expect Config to reject bad inputs; catching this keeps the fuzzer running
        pass
    except Exception as e:
        # If we get an unhandled crash, we want the fuzzer to stop
        raise RuntimeError(f"Config crashed on input: {e}") from e

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
