#!/usr/bin/env python3
"""Fuzz test for the SecretAuth requests.auth.AuthBase adapter.
Ensures credential masking and HTTP header injection do not crash under chaotic input.
"""

import logging
import sys
from unittest.mock import MagicMock

import atheris


with atheris.instrument_imports(enable_loader_override=False):
    from mailjet_rest.utils.guardrails import SecretAuth

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # Generate chaotic credential tuples
    pub_key = fdp.ConsumeUnicodeNoSurrogates(64)
    priv_key = fdp.ConsumeUnicodeNoSurrogates(64)

    try:
        # Initialize the custom auth adapter
        auth = SecretAuth((pub_key, priv_key))

        # Fuzz the __eq__ override
        _ = auth == (pub_key, priv_key)
        _ = auth == fdp.ConsumeUnicodeNoSurrogates(10)

        # Fuzz the __repr__ memory masking
        _ = repr(auth)

        # Fuzz the requests dispatch __call__ injection
        mock_request = MagicMock()
        mock_request.headers = {}

        # This will trigger requests.auth._basic_auth_str natively
        auth(mock_request)

        # Ensure the header was attached successfully
        if "Authorization" not in mock_request.headers:
            raise RuntimeError("CRASH: SecretAuth failed to attach the Authorization header.")

    except (ValueError, TypeError):
        # Expected if the underlying standard library rejects specific malformed encodings
        pass
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in SecretAuth: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
