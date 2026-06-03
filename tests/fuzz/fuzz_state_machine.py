"""Atheris target for Stateful/Temporal execution manipulation."""
import atheris
import sys
from typing import Any
from unittest.mock import MagicMock

with atheris.instrument_imports():
    from mailjet_rest import Client
    from mailjet_rest.builders import MessageBuilder
    from mailjet_rest.config import Config
    from mailjet_rest.errors import ApiError

def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return
    fdp = atheris.FuzzedDataProvider(data)

    try:
        # Initialize base state with mocked API caller to prevent real network calls
        client = Client(auth=("key", "sec"))
        client.api_call = MagicMock(return_value=MagicMock(status_code=200, json=lambda: {"Data": []}))  # type: ignore[method-assign]
        builder = MessageBuilder()

        num_operations = fdp.ConsumeIntInRange(1, 10)
        for _ in range(num_operations):
            op = fdp.ConsumeIntInRange(0, 5)

            if op == 0:
                client.config = Config(api_url=fdp.ConsumeUnicodeNoSurrogates(20))
            elif op == 1:
                builder.add_recipient(fdp.ConsumeUnicodeNoSurrogates(10))
            elif op == 2:
                builder._msg = {}
            elif op == 3:
                payload = builder.build()
                client._execute_request("POST", "https://api.mailjet.com/v3/send", data=payload)  # type: ignore[call-arg]
            elif op == 4:
                client.auth = (fdp.ConsumeUnicodeNoSurrogates(5), None)  # type: ignore[attr-defined]

            # API Lifecycle Simulation (CRUD Chaos)
            elif op == 5:
                endpoint_name = fdp.PickValueInList(["template", "contact", "campaign", "sender"])
                ep = getattr(client, endpoint_name)
                fuzzed_id = fdp.ConsumeInt(100000) if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(15)
                fuzzed_data = {fdp.ConsumeUnicodeNoSurrogates(5): fdp.ConsumeUnicodeNoSurrogates(10)}

                # Execute sequential lifecycle Operations rapidly
                ep.create(data=fuzzed_data)
                ep.get(id=fuzzed_id)
                ep.update(id=fuzzed_id, data=fuzzed_data)
                ep.delete(id=fuzzed_id)

    except (ValueError, TypeError, AttributeError, KeyError, ApiError):
        # We expect validation drops, but NOT memory corruption or unhandled runtime faults
        pass

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
