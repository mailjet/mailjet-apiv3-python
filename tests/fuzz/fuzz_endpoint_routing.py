#!/usr/bin/env python3
"""Fuzz test for Immutable Route Mapping and URI Interpolation.
Tests the fail-closed nature of _build_url inside mailjet_rest.endpoint.Endpoint
"""

import logging
import sys
from unittest.mock import MagicMock

import atheris


with atheris.instrument_imports():
    from mailjet_rest.client import Client
    from mailjet_rest.endpoint import Endpoint

logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 5:
        return

    fdp = atheris.FuzzedDataProvider(data)

    # 1. Setup Mocked Dependencies
    mock_client = MagicMock(spec=Client)

    # Explicitly mock the 'config' instance attribute before setting properties on it
    mock_client.config = MagicMock()
    mock_client.config.version = fdp.ConsumeUnicodeNoSurrogates(5) or "v3"
    mock_client.config.api_url = fdp.ConsumeUnicodeNoSurrogates(20) or "https://api.mailjet.com/"

    # 2. Fuzz the exact route key resolution against the immutable ROUTE_MAP
    # The route key could be "send", "contact", "contactslist_csvdata", or total garbage
    endpoint_name = fdp.ConsumeUnicodeNoSurrogates(30)

    try:
        ep = Endpoint(client=mock_client, name=endpoint_name)

        id_val: str | int | None = None
        action_id: str | int | None = None

        # Chaotic typing for the ID injection
        choice1 = fdp.ConsumeIntInRange(0, 2)
        if choice1 == 1:
            id_val = fdp.ConsumeInt(100)
        elif choice1 == 2:
            id_val = fdp.ConsumeUnicodeNoSurrogates(15)

        # Chaotic typing for the Action ID injection
        choice2 = fdp.ConsumeIntInRange(0, 2)
        if choice2 == 1:
            action_id = fdp.ConsumeInt(100)
        elif choice2 == 2:
            action_id = fdp.ConsumeUnicodeNoSurrogates(15)

        # Trigger the URI interpolation engine
        url = ep._build_url(id_val=id_val, action_id=action_id)

        # Ensure the method strictly upholds the return contract
        if not isinstance(url, str):
            raise RuntimeError(f"CRASH: URI Builder returned non-string: {type(url)}")

    except (ValueError, TypeError, KeyError):
        # We expect validation failures for malformed IDs or bad schema keys
        pass
    except Exception as e:
        raise RuntimeError(f"UNHANDLED CRASH in Endpoint._build_url: {type(e).__name__} - {e}") from e


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
