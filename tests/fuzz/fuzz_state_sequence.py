#!/usr/bin/env python3
"""Executes rapid-fire sequences of Mailjet Client operations to isolate
CPU/Memory leaks and instance-level state corruption.
"""

import logging
import sys
import typing
from collections.abc import Callable
from unittest.mock import Mock

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest import Client
    from mailjet_rest.errors import ApiError, ValidationError

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)
    client = Client(auth=("test", "test"), version="v3")

    # Mock network to isolate the CPU on internal SDK memory mutations
    client.session.request = Mock(return_value=Mock(status_code=200, json=dict))  # type: ignore[method-assign]

    # A pool of operational mutations
    actions: list[Callable[[], typing.Any]] = [
        lambda: client.contact.create(data={"Email": fdp.ConsumeUnicodeNoSurrogates(15)}),
        lambda: client.contact.get(id=fdp.ConsumeInt(10000)),
        lambda: client.send.create(data={"Messages": []}),
        lambda: setattr(client.config, "timeout", fdp.ConsumeFloat()),
        lambda: client.template.update(id=fdp.ConsumeInt(100), data={"Name": fdp.ConsumeUnicodeNoSurrogates(10)}),
    ]

    # Execute between 1 and 50 rapid-fire operations on the identical client memory object
    num_steps = fdp.ConsumeIntInRange(1, 50)

    try:
        for _ in range(num_steps):
            action = fdp.PickValueInList(actions)
            action()

    except (ApiError, ValueError, TypeError, AttributeError, ValidationError, KeyError):
        # Expected validation exceptions traversing state sequence.
        pass
    except Exception as e:
        raise RuntimeError(f"SEQUENCE CRASH: Unhandled memory/state fault: {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
