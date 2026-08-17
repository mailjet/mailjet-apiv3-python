#!/usr/bin/env python3
"""Fuzz test for Pagination Cursor and Streaming logic.
Simulates a chaotic or malicious API server returning bad schema types.
"""

import logging
import sys
from unittest.mock import MagicMock

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest.client import Client
    from mailjet_rest.endpoint import Endpoint

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    mock_client = MagicMock(spec=Client)
    mock_client.config = MagicMock()
    mock_client.config.version = "v3"
    mock_client.config.api_url = "https://api.mailjet.com/"

    endpoint = Endpoint(client=mock_client, name="contact")

    # Simulate chaotic JSON responses from the Mailjet API
    def mock_api_call(*args, **kwargs):
        mock_response = MagicMock()

        # We fuzz the 'Data' key to be missing, an integer, a string, or a chaotic dict
        # This tests if `yield from` and `len(data)` crash the SDK
        choice = fdp.ConsumeIntInRange(0, 3)
        if choice == 0:
            payload = {"Data": fdp.ConsumeUnicodeNoSurrogates(20)}
        elif choice == 1:
            payload = {"Data": fdp.ConsumeInt(100)}
        elif choice == 2:
            payload = {}  # Missing entirely
        else:
            payload = {"Data": [{"ID": fdp.ConsumeInt(100)} for _ in range(fdp.ConsumeIntInRange(1, 5))]}

        mock_response.json.return_value = payload
        return mock_response

    mock_client.api_call.side_effect = mock_api_call

    try:
        gen = endpoint.stream(chunk_size=fdp.ConsumeIntInRange(-10, 100))

        # Consume the generator to trigger the internal logic
        for _ in range(fdp.ConsumeIntInRange(1, 5)):
            next(gen)

    except (ValueError, TypeError, StopIteration):
        # Safe rejections - The SDK or Python correctly caught the hostile payload iteration
        # StopIteration is expected when generator ends.
        pass
    except Exception as e:
        raise RuntimeError(f"CRASH: Stream generator raised unhandled exception: {type(e).__name__}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
