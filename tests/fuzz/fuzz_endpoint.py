import atheris
import sys

from mailjet_rest.endpoint import _route_send, _route_csv, _route_data

with atheris.instrument_imports():
    # Instrument the routing logic
    pass

def TestOneInput(data: bytes) -> None:
    """Fuzz target for URL routing and path construction."""
    if len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate random string inputs for all URL components
    base = fdp.ConsumeUnicodeNoSurrogates(10)
    ver = fdp.ConsumeUnicodeNoSurrogates(5)
    parts = [fdp.ConsumeUnicodeNoSurrogates(5), fdp.ConsumeUnicodeNoSurrogates(5)]
    id_val = fdp.ConsumeUnicodeNoSurrogates(10)
    action = fdp.ConsumeUnicodeNoSurrogates(5)
    name = fdp.ConsumeUnicodeNoSurrogates(10)

    try:
        # Fuzz the various routing methods
        _route_send(base, ver, parts, id_val, action, name)
        _route_csv(base, ver, parts, id_val, action, name)
        _route_data(base, ver, parts, id_val, action, name)

    except ValueError:
        # If the SDK router fails safely, it should raise a ValueError.
        # Let IndexError and TypeError crash the fuzzer!
        pass

    except Exception as e:
        # Any other exception indicates a crash in logic we need to investigate
        raise RuntimeError(f"Endpoint router crashed: {e}") from e

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
