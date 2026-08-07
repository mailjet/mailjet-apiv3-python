#!/usr/bin/env python3
"""
Fuzz test for Semantic Error Response Deserialization.
Ensures that native requests.RequestException instances are securely wrapped.
"""

import sys
import logging
from unittest.mock import MagicMock

import atheris
from requests.exceptions import RequestException

with atheris.instrument_imports():
    from mailjet_rest.client import Client
    from mailjet_rest.errors import ApiError

logging.disable(logging.CRITICAL)

def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Fuzz typical and chaotic API error status codes
    status_code = fdp.ConsumeIntInRange(100, 999)

    # 2. Fuzz the actual response body (HTML, massive JSON, half-written strings)
    content_text = fdp.ConsumeUnicodeNoSurrogates(1024)

    # Mock the HTTP Response object exactly as requests would attach it
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = content_text

    # Sometimes remove the response entirely (DNS failure simulation)
    if fdp.ConsumeBool():
        mock_response = None

    try:
        raw_exception = RequestException("Simulated Fuzzed Exception", response=mock_response)

        # The SDK should wrap ALL parsing errors inside the ApiError hierarchy safely
        Client._handle_api_error(raw_exception)

    except ApiError as e:
        # SECURITY SUCCESS: Safely mapped to a Domain Exception
        # Test the string representation to ensure formatters don't crash
        _ = str(e)
    except Exception as e:
        # ApiError mapper itself should never crash.
        raise RuntimeError(f"CRASH: Error mapper leaked native exception: {type(e).__name__} - {e}") from e

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
