import sys
import atheris
from unittest.mock import Mock

with atheris.instrument_imports():
    from mailjet_rest import Client

def TestOneInput(data: bytes) -> None:
    fdp = atheris.FuzzedDataProvider(data)

    # 1. Generate one piece of chaotic truth
    email_str = fdp.ConsumeUnicodeNoSurrogates(50)

    client_v3 = Client(auth=("test", "test"), version="v3")
    client_v31 = Client(auth=("test", "test"), version="v3.1")
    client_v3.session.request = Mock()  # type: ignore[method-assign]
    client_v31.session.request = Mock()  # type: ignore[method-assign]

    # 2. Inject it into both specifications
    payload_v3 = {
        "FromEmail": email_str,
        "FromName": "Test",
        "Subject": "Test",
        "Text-part": "Test",
        "Recipients": [{"Email": "target@example.com"}]
    }

    payload_v31 = {
        "Messages": [{
            "From": {"Email": email_str, "Name": "Test"},
            "To": [{"Email": "target@example.com"}],
            "Subject": "Test",
            "TextPart": "Test"
        }]
    }

    success_v3 = False
    success_v31 = False

    try:
        client_v3.send.create(data=payload_v3)
        success_v3 = True
    except (ValueError, TypeError): pass

    try:
        client_v31.send.create(data=payload_v31)
        success_v31 = True
    except (ValueError, TypeError): pass

    # 3. Differential Assertion
    if success_v3 != success_v31:
        # If the SDK's validation logic is mathematically asymmetrical, force a fuzzer crash
        raise AssertionError(
            f"Differential Mismatch on Email: {repr(email_str)} | v3: {success_v3}, v3.1: {success_v31}"
        )

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
