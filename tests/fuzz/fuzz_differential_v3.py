import sys
import atheris
from typing import Any

with atheris.instrument_imports():
    from mailjet_rest import Client

# ==========================================
# GLOBAL SETUP (Runs ONCE)
# ==========================================
client_v3 = Client(auth=("test", "test"), version="v3")
client_v31 = Client(auth=("test", "test"), version="v3.1")

# Create a "Dumb Mock" that doesn't record call history.
# This prevents the 2GB Out-Of-Memory (OOM) crash during heavy fuzzing.
class DumbResponse:
    status_code = 200
    def json(self) -> dict[str, Any]:
        return {}

    @property
    def text(self) -> str:
        return ""

def dumb_mock_request(*args: Any, **kwargs: Any) -> DumbResponse:
    return DumbResponse()

client_v3.session.request = dumb_mock_request  # type: ignore[method-assign, assignment]
client_v31.session.request = dumb_mock_request  # type: ignore[method-assign, assignment]


def TestOneInput(data: bytes) -> None:
    # Optional constraint: limit input size to avoid massive string allocation bottlenecks
    if len(data) > 254:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Generate one piece of chaotic truth
    email_str = fdp.ConsumeUnicodeNoSurrogates(50)

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

    # Expected during fuzzing: invalid payloads should be treated as unsuccessful sends.
    EXPECTED_REJECTIONS = (ValueError, TypeError)

    try:
        client_v3.send.create(data=payload_v3)
        success_v3 = True
    except EXPECTED_REJECTIONS as _exc:
        # Expected fuzzing-time validation rejection: keep success_v3 as False.
        _ = _exc

    try:
        client_v31.send.create(data=payload_v31)
        success_v31 = True
    except EXPECTED_REJECTIONS as _exc:
        # Expected fuzzing-time validation rejection: keep success_v31 as False.
        _ = _exc

    # 3. Differential Assertion
    if success_v3 != success_v31:
        # If the SDK's validation logic is mathematically asymmetrical, force a fuzzer crash
        raise AssertionError(
            f"Differential Mismatch on Email: {repr(email_str)} | v3: {success_v3} vs v3.1: {success_v31}"
        )

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
