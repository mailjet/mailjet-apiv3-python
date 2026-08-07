#!/usr/bin/env python3
"""Fuzz test for Network Resilience and 'Evil Server' payload handling.
Adapts Mailgun's robust requests.Session.send interception to test
how Mailjet handles chaotic upstream API JSON and connection drops.
"""

import contextlib
import json
import logging
import os
import pathlib
import sys
from typing import Any

import atheris
import requests


with atheris.instrument_imports():
    from mailjet_rest import Client
    from mailjet_rest.errors import ApiError

# Globally disable all SDK logging during fuzzing to maximize executions/sec
logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 20:
        return

    fdp = atheris.FuzzedDataProvider(data)
    client = Client(auth=("test", "test"), version="v3")

    # Intercept the exact requests.Session HTTP invocation
    original_send = client.session.send

    def evil_send(request: Any, **kwargs: Any) -> requests.Response:
        if fdp.ConsumeBool():
            # 1. Simulate violent network transport panics
            exceptions = [
                requests.exceptions.ConnectionError("Fuzzed Connection Drop"),
                requests.exceptions.Timeout("Fuzzed Timeout"),
                requests.exceptions.TooManyRedirects("Infinite Redirect Loop"),
                requests.exceptions.ChunkedEncodingError("Fuzzed Chunk Error"),
            ]
            raise fdp.PickValueInList(exceptions)

        # 2. Simulate malformed upstream API JSON and semantic error payloads
        resp = requests.Response()
        resp.status_code = fdp.PickValueInList([200, 400, 401, 403, 429, 500, 502, 503])

        # Fuzz the body (could be HTML, half-written JSON, or binary garbage)
        resp._content = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1024))

        # Inject malformed or bizarre Content-Type headers
        resp.headers = {
            fdp.ConsumeUnicodeNoSurrogates(16): fdp.ConsumeUnicodeNoSurrogates(32),
            "Content-Type": fdp.PickValueInList(["application/json", "text/html", "unknown/unknown"]),
        }  # type: ignore[assignment]

        resp.request = request
        return resp

    client.session.send = evil_send  # type: ignore[method-assign]

    # 3. Brutally silence ALL output (stdout, stderr) during the fuzzing iteration
    with (
        pathlib.Path(os.devnull).open("w") as devnull,
        contextlib.redirect_stdout(devnull),
        contextlib.redirect_stderr(devnull),
    ):
        try:
            # Trigger the malicious payload response
            client.send.create(data={"dummy": "data"})

        except (ApiError, requests.exceptions.RequestException, json.JSONDecodeError, ValueError, TypeError):
            # SUCCESS: The SDK gracefully caught the garbage and wrapped/rejected it.
            pass
        except Exception as e:
            # UNHANDLED CRASH: If we leak a native RecursionError, KeyError, or MemoryError
            raise RuntimeError(f"CRITICAL: SDK crashed handling Evil Server response: {type(e).__name__} - {e}") from e

    # Restore the mock to avoid state bleed
    client.session.send = original_send  # type: ignore[method-assign]


if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
