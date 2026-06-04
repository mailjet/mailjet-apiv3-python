import atheris
import sys
import logging
from typing import Any
from unittest.mock import patch

import requests
from mailjet_rest.errors import MailjetAuthError, CriticalApiError, ApiError, ValidationError


with atheris.instrument_imports():
    from mailjet_rest.client import Client

# Suppress the SDK's noisy error logging during fuzzing
logging.getLogger("mailjet_rest").setLevel(logging.CRITICAL + 1)

def TestOneInput(data: bytes) -> None:
    if len(data) < 10:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # ---------------------------------------------------------
    # Fuzzing Authentication Modes (Basic Tuple vs Bearer)
    # ---------------------------------------------------------
    auth: Any
    auth_mode = fdp.ConsumeIntInRange(0, 2)
    if auth_mode == 0:
        # Tuple Auth (Basic)
        auth = (fdp.ConsumeUnicodeNoSurrogates(10), fdp.ConsumeUnicodeNoSurrogates(10))
    elif auth_mode == 1:
        # String Auth (Bearer Token)
        auth = fdp.ConsumeUnicodeNoSurrogates(20)
    else:
        # Malformed Auth Tuple (e.g. wrong size/types)
        auth = (fdp.ConsumeInt(10),)  # pyright: ignore[reportArgumentType]

    # ---------------------------------------------------------
    # Fuzzing API Versioning
    # ---------------------------------------------------------
    versions = ["v1", "v3", "v3.1", fdp.ConsumeUnicodeNoSurrogates(5)]
    fuzzed_version = fdp.PickValueInList(versions)

    try:
        # Client initialization is now dynamically fuzzed per execution
        client = Client(auth=auth, version=fuzzed_version)  # type: ignore[arg-type]  # pyright: ignore[reportArgumentType]
    except (ValueError, TypeError, ValidationError):
        # SDK successfully blocked invalid configuration; move to next mutation
        return

    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", fdp.ConsumeUnicodeNoSurrogates(5)]
    method = fdp.PickValueInList(valid_methods)
    if method not in valid_methods:
        method = "GET"

    url = fdp.ConsumeUnicodeNoSurrogates(50)
    payload = fdp.ConsumeBytes(100)

    try:
        def mock_request(*args: Any, **kwargs: Any) -> Any:
            # Chance to simulate a violent network drop
            if fdp.ConsumeBool() and fdp.ConsumeBool():
                exceptions = [
                    requests.exceptions.ConnectionError("Fuzzed Connection Drop"),
                    requests.exceptions.Timeout("Fuzzed Timeout"),
                    requests.exceptions.ChunkedEncodingError("Fuzzed Chunk Error")
                ]
                raise fdp.PickValueInList(exceptions)

            headers = kwargs.get("headers", {})
            for key, val in headers.items():
                if "\n" in str(val) or "\r" in str(val):
                    raise RuntimeError(f"CRLF bypassed in header! {key}: {val}")

            # Poison the Response!
            resp = requests.Response()
            resp.status_code = fdp.ConsumeIntInRange(200, 599)
            resp.headers = {  # type: ignore[assignment]
                fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(20)
            }
            resp._content = fdp.ConsumeBytes(150)
            return resp

        malicious_headers = {
            fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(30)
        }

        with patch.object(client.session, 'request', side_effect=mock_request):
            client.api_call(
                method=method,
                url=url,
                data=payload,
                headers=malicious_headers
            )

        chaotic_dict = {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(10)}
        client._extract_telemetry(chaotic_dict, None)

    except (ValueError, TypeError, MailjetAuthError, CriticalApiError, ApiError, ValidationError, requests.exceptions.RequestException):
        # Silently catch all expected routing, validation, and mocked network errors
        pass

def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
