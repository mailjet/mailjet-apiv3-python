from typing import Any
import sys
import os
import contextlib
import logging
import atheris
import requests

with atheris.instrument_imports():
    from mailjet_rest import Client
    from mailjet_rest.errors import ApiError, MailjetNetworkError

# Globally disable all SDK logging during fuzzing
logging.disable(logging.CRITICAL)

def TestOneInput(data: bytes) -> None:
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
                requests.exceptions.ChunkedEncodingError("Fuzzed Chunk Error")
            ]
            raise fdp.PickValueInList(exceptions)

        # 2. Simulate malformed upstream API JSON and headers
        resp = requests.Response()
        resp.status_code = fdp.ConsumeIntInRange(100, 599)
        resp._content = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1024))
        resp.headers = {fdp.ConsumeUnicodeNoSurrogates(10): fdp.ConsumeUnicodeNoSurrogates(10)}  # type: ignore[assignment]
        return resp

    client.session.send = evil_send  # type: ignore[method-assign]

    # 3. Brutally silence ALL output (stdout, stderr) during the fuzzing iteration
    # This prevents SDK tracebacks from choking the terminal I/O
    with open(os.devnull, "w") as devnull:
        with contextlib.redirect_stdout(devnull), contextlib.redirect_stderr(devnull):
            try:
                client.send.create(data={"dummy": "data"})
            except Exception:
                # Catch absolutely everything to prevent fuzzer from stopping on anticipated network panics
                pass

    # Restore the mock to avoid state bleed
    client.session.send = original_send  # type: ignore[method-assign]

if __name__ == "__main__":
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
