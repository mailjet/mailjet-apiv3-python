#!/usr/bin/env python3
"""Atheris target for Stateful/Temporal execution manipulation.
Tracks entity IDs to accurately simulate CRUD lifecycles in rapid succession.
"""

import contextlib
import logging
import sys
from unittest.mock import MagicMock

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest import Client
    from mailjet_rest.builders import MessageBuilder
    from mailjet_rest.config import Config
    from mailjet_rest.errors import ApiError, ValidationError

_DEVNULL = sys.stderr
logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)
    active_ids: list[str] = []  # Track state to perform realistic updates/deletes

    try:
        # Initialize base state with mocked API caller to prevent real network calls
        client = Client(auth=("key", "sec"))
        client.api_call = MagicMock(return_value=MagicMock(status_code=200, json=lambda: {"Data": []}))  # type: ignore[method-assign]
        builder = MessageBuilder()

        num_operations = fdp.ConsumeIntInRange(1, 15)

        with contextlib.redirect_stdout(_DEVNULL), contextlib.redirect_stderr(_DEVNULL):
            for _ in range(num_operations):
                op = fdp.ConsumeIntInRange(0, 5)

                if op == 0:
                    client.config = Config(api_url=fdp.ConsumeUnicodeNoSurrogates(20))
                elif op == 1:
                    builder.add_recipient(fdp.ConsumeUnicodeNoSurrogates(10))
                elif op == 2:
                    builder._payload = {}
                elif op == 3:
                    payload = builder.build()
                    # Leveraging explicitly requested orchestration method
                    client.api_call("POST", "https://api.mailjet.com/v3/send", data=payload)
                elif op == 4:
                    client.auth = (fdp.ConsumeUnicodeNoSurrogates(5), None)  # type: ignore[attr-defined, assignment]

                # API Lifecycle Simulation (Stateful CRUD Chaos)
                elif op == 5:
                    endpoint_name = fdp.PickValueInList(["template", "contact", "campaign", "sender"])
                    ep = getattr(client, endpoint_name)

                    crud_op = fdp.ConsumeIntInRange(0, 3)
                    fuzzed_data = {fdp.ConsumeUnicodeNoSurrogates(5): fdp.ConsumeUnicodeNoSurrogates(10)}

                    if crud_op == 0:  # CREATE
                        new_id = fdp.ConsumeUnicodeNoSurrogates(10)
                        ep.create(data={"ID": new_id, **fuzzed_data})
                        active_ids.append(new_id)

                    elif crud_op == 1 and active_ids:  # GET
                        ep.get(id=fdp.PickValueInList(active_ids))

                    elif crud_op == 2 and active_ids:  # UPDATE
                        ep.update(id=fdp.PickValueInList(active_ids), data=fuzzed_data)

                    elif crud_op == 3 and active_ids:  # DELETE
                        target_id = fdp.PickValueInList(active_ids)
                        ep.delete(id=target_id)
                        active_ids.remove(target_id)

    except (ValueError, TypeError, AttributeError, KeyError, ApiError, ValidationError):
        # We expect validation drops, but NOT memory corruption or unhandled runtime faults
        pass
    except Exception as e:
        raise RuntimeError(f"STATEFUL CRASH: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
