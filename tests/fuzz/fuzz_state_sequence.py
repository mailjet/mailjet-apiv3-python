import sys
import atheris
from unittest.mock import Mock

with atheris.instrument_imports():
    from mailjet_rest import Client
    from mailjet_rest.errors import ApiError

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)
    client = Client(auth=("test", "test"), version="v3")

    # Mock network to isolate the CPU on internal SDK memory mutations
    client.session.request = Mock(return_value=Mock(status_code=200, json=lambda: {}))  # type: ignore[method-assign]

    # A pool of operational mutations
    actions = [
        lambda: client.contact.create(data={"Email": fdp.ConsumeUnicodeNoSurrogates(15)}),
        lambda: client.contact.get(id=fdp.ConsumeInt(10000)),
        lambda: client.send.create(data={"Messages": []}),
        lambda: setattr(client.config, 'timeout', fdp.ConsumeFloat()),
        lambda: client.template.update(id=fdp.ConsumeInt(100), data={"Name": fdp.ConsumeUnicodeNoSurrogates(10)})
    ]

    # Execute between 1 and 50 rapid-fire operations on the same object
    num_steps = fdp.ConsumeIntInRange(1, 50)

    try:
        for _ in range(num_steps):
            action = fdp.PickValueInList(actions)
            action()
    except (ApiError, ValueError, TypeError, AttributeError):
        # We expect validation errors. We are hunting for core interpreter panics.
        pass

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
