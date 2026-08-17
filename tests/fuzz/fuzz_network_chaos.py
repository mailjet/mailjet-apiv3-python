#!/usr/bin/env python3
"""Atheris Fuzzing Target: Network Fault Injection & Chaos Monkey.

Stresses the Mailjet SDK Client against upstream transport failures,
socket-level drops, urllib3 protocol errors, and malformed streaming responses.
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
import urllib3.exceptions


# 1. Instrument SDK modules
with atheris.instrument_imports():
    from mailjet_rest import Client
    from mailjet_rest.errors import ApiError, ValidationError

# Disable internal SDK loggers to maximize executions/sec
logging.disable(logging.CRITICAL)


def TestOneInput(data: bytes) -> None:
    if len(data) < 16:
        return

    fdp = atheris.FuzzedDataProvider(data)
    client = Client(auth=("mock_api_key", "mock_secret_key"), version="v3")

    original_send = client.session.send

    def chaotic_send(request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:
        # Determine the type of network chaos to inject
        chaos_mode = fdp.ConsumeIntInRange(0, 3)

        # -----------------------------------------------------------
        # MODE 0: Low-Level urllib3 Socket & Protocol Panics
        # -----------------------------------------------------------
        if chaos_mode == 0:
            urllib3_exceptions = [
                urllib3.exceptions.ProtocolError("Fuzzed: Socket connection broken or reset"),
                urllib3.exceptions.DecodeError("Fuzzed: Corrupted response compression/encoding"),
                urllib3.exceptions.ReadTimeoutError(
                    pool=None,  # type: ignore[arg-type]
                    url=request.url or "https://api.mailjet.com",
                    message="Fuzzed: Read timed out on socket stream",
                ),
                urllib3.exceptions.SSLError("Fuzzed: TLS/SSL handshake negotiation panic"),
                urllib3.exceptions.ResponseNotChunked("Fuzzed: Expected chunked payload framing"),
            ]
            raise fdp.PickValueInList(urllib3_exceptions)

        # -----------------------------------------------------------
        # MODE 1: Mid-Tier requests Transport Failures
        # -----------------------------------------------------------
        if chaos_mode == 1:
            requests_exceptions = [
                requests.exceptions.ConnectionError("Fuzzed: Remote host closed connection"),
                requests.exceptions.Timeout("Fuzzed: Request connection/read timed out"),
                requests.exceptions.ChunkedEncodingError("Fuzzed: Incomplete chunk stream received"),
                requests.exceptions.ContentDecodingError("Fuzzed: Failed to decode compressed stream"),
                requests.exceptions.TooManyRedirects("Fuzzed: Infinite 30x redirection loop"),
            ]
            raise fdp.PickValueInList(requests_exceptions)

        # -----------------------------------------------------------
        # MODE 2: Evil Server Responses (Malformed Bodies & Headers)
        # -----------------------------------------------------------
        resp = requests.Response()
        resp.request = request

        # Status Code: Standard, Gateway Panics, or Out-of-Range Codes
        resp.status_code = fdp.PickValueInList([
            200, 204, 400, 401, 403, 404, 422, 429, 500, 502, 503, 504,
            fdp.ConsumeIntInRange(100, 599),
        ])

        # Chaotic Header Injection
        headers: dict[str, str] = {
            "Content-Type": fdp.PickValueInList([
                "application/json",
                "application/json; charset=utf-8",
                "text/html; charset=iso-8859-1",
                "application/octet-stream",
                fdp.ConsumeUnicodeNoSurrogates(32),
            ]),
        }
        # Add random fuzzed headers
        for _ in range(fdp.ConsumeIntInRange(0, 4)):
            headers[fdp.ConsumeUnicodeNoSurrogates(16)] = fdp.ConsumeUnicodeNoSurrogates(32)
        resp.headers = requests.structures.CaseInsensitiveDict(headers)

        # Payload Chaos: Binary garbage, truncated JSON, or extreme strings
        content_size = fdp.ConsumeIntInRange(0, 2048)
        resp._content = fdp.ConsumeBytes(content_size)

        return resp

    # Mount the network chaos interceptor
    client.session.send = chaotic_send  # type: ignore[method-assign]

    # Silence stdout/stderr during violent parsing failures
    with (
        pathlib.Path(os.devnull).open("w") as devnull,
        contextlib.redirect_stdout(devnull),
        contextlib.redirect_stderr(devnull),
    ):
        try:
            # Trigger API calls across different dynamic endpoints
            endpoint_name = fdp.PickValueInList(["send", "contact", "template", "campaign"])
            endpoint = getattr(client, endpoint_name)

            operation = fdp.ConsumeIntInRange(0, 2)
            dummy_payload = {"TextPart": fdp.ConsumeUnicodeNoSurrogates(50)}

            if operation == 0:
                endpoint.create(data=dummy_payload)
            elif operation == 1:
                endpoint.get(id=fdp.ConsumeUnicodeNoSurrogates(10))
            else:
                endpoint.delete(id=fdp.ConsumeUnicodeNoSurrogates(10))

        except (
            ApiError,
            ValidationError,
            requests.exceptions.RequestException,
            urllib3.exceptions.HTTPError,
            json.JSONDecodeError,
            ValueError,
            TypeError,
        ):
            # SUCCESS: The SDK gracefully caught, wrapped, or rejected the network fault.
            pass

        except Exception as e:
            # UNHANDLED FAULT: Leaked native crashes (KeyError, RecursionError, MemoryError)
            raise RuntimeError(
                f"UNHANDLED NETWORK CHAOS CRASH: {type(e).__name__} -> {e}"
            ) from e

        finally:
            # Prevent state bleeding across Atheris iterations
            client.session.send = original_send  # type: ignore[method-assign]


def main() -> None:
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
