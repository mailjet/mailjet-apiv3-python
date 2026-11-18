#!/usr/bin/env python3
"""Fuzz test for Semantic Error Response Deserialization.
Ensures that native requests.RequestException instances are securely wrapped.
"""

import json
import logging
import sys
from types import SimpleNamespace

import atheris
from requests.exceptions import RequestException


with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import Client
    from mailjet_rest.errors import ApiError, raise_mapped_http_error

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Fuzz typical and chaotic API error status codes
    status_code = fdp.ConsumeIntInRange(100, 999)

    # 2. Fuzz the actual response body (HTML, valid Mailjet error JSON, malformed JSON)
    content_text = fdp.ConsumeUnicodeNoSurrogates(1024)
    json_mode = fdp.ConsumeIntInRange(0, 3)

    def _fake_json() -> object:
        if json_mode == 0:
            return {"ErrorMessage": content_text[:120], "ErrorInfo": content_text[120:240], "StatusCode": status_code}
        if json_mode == 1:
            return {"Messages": [{"Errors": [{"ErrorMessage": content_text[:120], "ErrorCode": "mj-001"}]}]}
        if json_mode == 2:
            return [content_text[:64]]
        return json.loads(content_text)

    mock_response: SimpleNamespace | None = SimpleNamespace(
        status_code=status_code,
        text=content_text,
        headers={"Retry-After": fdp.ConsumeUnicodeNoSurrogates(16)},
        json=_fake_json,
    )

    # Sometimes remove the response entirely (DNS failure simulation)
    if fdp.ConsumeBool():
        mock_response = None

    raw_exception = RequestException("Simulated Fuzzed Exception", response=mock_response)  # type: ignore[arg-type]

    try:
        # The SDK should wrap ALL parsing errors inside the ApiError hierarchy safely
        Client._handle_api_error(raw_exception)

    except ApiError as e:
        # SECURITY SUCCESS: Safely mapped to a Domain Exception
        # Test the string representation to ensure formatters don't crash
        _ = str(e)
    except Exception as e:
        # ApiError mapper itself should never crash.
        raise RuntimeError(f"CRASH: Error mapper leaked native exception: {type(e).__name__} - {e}") from e

    if mock_response is not None:
        try:
            raise_mapped_http_error(mock_response, raw_exception)
        except ApiError as e:
            _ = str(e)


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
