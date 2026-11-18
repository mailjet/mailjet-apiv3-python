#!/usr/bin/env python3
"""Asynchronous 'Evil Server' fuzz test for AsyncClient and AsyncEndpoint.

Simulates upstream httpx2 transport panics, corrupted byte streams,
and malformed JSON bodies during async mutations and stream() pagination.
"""

from __future__ import annotations

import asyncio
import gc
import json
import logging
import sys
import warnings
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import AsyncClient, _httpx2 as httpx2
    from mailjet_rest.errors import ApiError, MailjetApiError


_loop = asyncio.new_event_loop()
_aclient = AsyncClient(auth=("test", "test"), version="v3", max_retries=0) if httpx2 is not None else None
_exec_count = 0


async def _run_evil_async_iteration(fdp: atheris.FuzzedDataProvider) -> None:
    httpx2_mod = httpx2
    aclient = _aclient
    if httpx2_mod is None or aclient is None:
        return

    async def evil_async_request(**kwargs: Any) -> Any:
        req = httpx2_mod.Request(kwargs.get("method", "GET"), kwargs.get("url", "https://api.mailjet.com/v3/send"))
        if fdp.ConsumeBool():
            exceptions = [
                httpx2_mod.TimeoutException("Fuzzed Async Timeout"),
                httpx2_mod.ConnectError("Fuzzed Async Connect Error"),
                httpx2_mod.NetworkError("Fuzzed Async Network Drop"),
                httpx2_mod.RemoteProtocolError("Fuzzed HTTP/2 Protocol Violation"),
            ]
            raise fdp.PickValueInList(exceptions)

        status = fdp.PickValueInList([200, 201, 204, 400, 401, 403, 404, 429, 500, 502, 503])
        raw_content = fdp.ConsumeBytes(fdp.ConsumeIntInRange(0, 1024))
        content_type = fdp.PickValueInList(["application/json", "text/plain", "text/html"])
        return httpx2_mod.Response(
            status_code=status,
            content=raw_content,
            headers={"Content-Type": content_type},
            request=req,
        )

    sess: Any = aclient.session
    sess.request = evil_async_request

    if fdp.ConsumeBool():
        await aclient.send.create(data={"dummy": fdp.ConsumeUnicodeNoSurrogates(32)})
    else:
        count = 0
        async for _ in aclient.contact.stream(chunk_size=fdp.ConsumeIntInRange(1, 10)):
            count += 1
            if count > 3:
                break


def TestOneInput(data: bytes) -> None:
    global _exec_count
    _exec_count += 1
    if _exec_count % 2000 == 0:
        gc.collect()

    if len(data) < 20 or httpx2 is None:
        return

    fdp = atheris.FuzzedDataProvider(data)
    try:
        _loop.run_until_complete(_run_evil_async_iteration(fdp))
    except (ApiError, MailjetApiError, httpx2.HTTPError, json.JSONDecodeError, ValueError, TypeError):
        return  # Expected transport, JSON, and validation rejections from fuzzed upstream responses.
    except Exception as e:
        msg = f"CRITICAL: AsyncClient crashed handling Evil Server response: {type(e).__name__} - {e}"
        raise RuntimeError(msg) from e


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
