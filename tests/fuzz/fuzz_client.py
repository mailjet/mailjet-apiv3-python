import atheris
import sys
from typing import Any
from unittest.mock import patch

import requests
from mailjet_rest.errors import MailjetAuthError, ValidationError


# Instrument the client to watch for crashes
with atheris.instrument_imports():
    from mailjet_rest.client import Client

# Initialize a client with dummy data
client = Client(auth=("fake_key", "fake_secret"), version="v3")

def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Fuzz the HTTP method
    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", fdp.ConsumeUnicodeNoSurrogates(5)]
    method = fdp.PickValueInList(valid_methods)
    if method not in valid_methods:
        method = "GET"

    # 2. Fuzz the URL
    url = fdp.ConsumeUnicodeNoSurrogates(50)

    # 3. Fuzz payload and headers
    payload = fdp.ConsumeBytes(100)

    try:
        # We don't want to actually make network calls.
        # We only want to test the 'Preparation' phase (parameter parsing/validation).
        # We mock the session.request to stop execution after preparation.
        def mock_request(*args: Any, **kwargs: Any) -> Any:
            return requests.Response()

        with patch.object(client.session, 'request', side_effect=mock_request):
            client.api_call(
                method=method,
                url=url,
                data=payload
            )
    except (ValueError, MailjetAuthError):
        # These are expected security/validation exceptions, not crashes.
        pass
    except Exception as e:
        # This catches unexpected logic crashes (e.g., bad URL parsing)
        raise RuntimeError(f"Client crashed on input: {e}") from e

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
