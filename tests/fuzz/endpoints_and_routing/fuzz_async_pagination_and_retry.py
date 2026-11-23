#!/usr/bin/env python3
"""Atheris fuzzing target for AsyncEndpoint.stream(), seekable stream rewind, and async retry execution."""

from __future__ import annotations

import asyncio
import contextlib
import io
import logging
import math
import sys
import warnings
from typing import Any
from unittest.mock import MagicMock

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import AsyncClient, _httpx2 as httpx2
    from mailjet_rest.endpoint import AsyncEndpoint
    from mailjet_rest.errors import ApiError, MailjetApiError
    from mailjet_rest.utils.retry import (
        RETRY_ALLOWED_METHODS,
        TRANSIENT_STATUS_CODES,
        compute_retry_delay,
        parse_retry_after_http_date,
        reset_stream_pointers,
        run_async_with_retries,
        snapshot_stream_offsets,
    )


_loop = asyncio.new_event_loop()
_base_async_client: AsyncClient | None = (
    AsyncClient(auth=("fuzz_pub_key", "fuzz_priv_key"), max_retries=0) if httpx2 is not None else None
)
_SILENT_LOGGER = logging.getLogger("mailjet_rest.fuzz_retry_silent")
_SILENT_LOGGER.propagate = False


class _NonSeekableStream:
    """Slotted non-seekable stream verifying snapshot/reset skips non-seekable objects."""

    __slots__ = ("closed",)

    def __init__(self, *, closed: bool = False) -> None:
        self.closed = closed

    def seekable(self) -> bool:
        return False

    def seek(self, _offset: int) -> int:
        msg = "Non-seekable stream must not have seek() invoked"
        raise AssertionError(msg)


async def _fuzz_async_stream(fdp: atheris.FuzzedDataProvider) -> None:
    mock_client = MagicMock(spec=AsyncClient)
    mock_client.config = MagicMock()
    mock_client.config.version = fdp.PickValueInList(["v3", "v3.1"])
    mock_client.config.api_url = "https://api.mailjet.com/"

    page_count = fdp.ConsumeIntInRange(0, 4)

    async def fake_api_call(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal page_count
        resp = MagicMock()
        resp.status_code = 200
        resp.text = ""
        resp.raise_for_status = lambda: None
        mode_body = fdp.ConsumeIntInRange(0, 4)
        if page_count <= 0:
            resp.json.return_value = {"Data": []}
            return resp
        page_count -= 1
        if mode_body == 0:
            resp.json.return_value = {"Data": [{"ID": i} for i in range(fdp.ConsumeIntInRange(1, 5))]}
        elif mode_body == 1:
            resp.json.side_effect = ValueError("bad json")
        elif mode_body == 2:
            resp.json.return_value = ["unexpected-list"]
        elif mode_body == 3:
            resp.json.return_value = {"Data": "not-a-list"}
        else:
            resp.json.return_value = {"Data": None}
        return resp

    mock_client.api_call = fake_api_call
    endpoint = AsyncEndpoint(client=mock_client, name="contact")

    chunk_size: Any = True if fdp.ConsumeIntInRange(0, 19) == 0 else fdp.ConsumeIntInRange(-3, 1050)
    max_items: Any = (
        False if fdp.ConsumeIntInRange(0, 19) == 0 else (fdp.ConsumeIntInRange(-2, 12) if fdp.ConsumeBool() else None)
    )
    method: Any = fdp.PickValueInList(["GET", "GET", "POST", "DELETE"])
    filters: dict[str, Any] = {}
    if fdp.ConsumeBool():
        filters["Offset"] = fdp.PickValueInList([0, 2, -1, "bad_offset"])

    yielded = 0
    expect_arg_error = (
        method.upper() != "GET"
        or isinstance(chunk_size, bool)
        or not isinstance(chunk_size, int)
        or chunk_size < 1
        or chunk_size > 1000
        or (max_items is not None and (isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0))
    )

    try:
        async with contextlib.aclosing(
            endpoint.stream(chunk_size=chunk_size, max_items=max_items, method=method, filters=filters)
        ) as agen:
            async for _ in agen:
                yielded += 1
    except ValueError:
        return
    except MailjetApiError:
        return

    if expect_arg_error:
        msg = f"AsyncEndpoint.stream accepted invalid args chunk_size={chunk_size!r}, max_items={max_items!r}, method={method!r}"
        raise AssertionError(msg)
    if max_items is not None and yielded > max_items:
        msg = f"AsyncEndpoint.stream exceeded max_items={max_items}: yielded={yielded}"
        raise AssertionError(msg)


def _fuzz_stream_rewind(fdp: atheris.FuzzedDataProvider) -> None:
    initial_a = fdp.ConsumeIntInRange(0, 8)
    initial_b = fdp.ConsumeIntInRange(0, 8)
    stream_a = io.BytesIO(b"0123456789abcdef")
    stream_a.seek(initial_a)
    stream_b = io.BytesIO(b"fedcba9876543210")
    stream_b.seek(initial_b)
    closed_stream = io.BytesIO(b"closed")
    closed_stream.close()
    non_seekable = _NonSeekableStream()

    # Depth-2 under `data` and depth-3 under `files` remain within max traversal depth <= 4.
    data_payload: Any = {"body": [stream_a, non_seekable, {"ignored": closed_stream}]}
    files_payload: Any = [("doc", ("doc.txt", stream_b, "text/plain"))]

    offsets = snapshot_stream_offsets(data_payload, files_payload)
    if offsets.get(id(stream_a)) != initial_a or offsets.get(id(stream_b)) != initial_b:
        msg = f"snapshot_stream_offsets captured wrong positions: {offsets!r}"
        raise AssertionError(msg)

    _ = stream_a.read(fdp.ConsumeIntInRange(1, 6))
    _ = stream_b.read(fdp.ConsumeIntInRange(1, 6))
    reset_stream_pointers(data_payload, files_payload, offsets)

    if stream_a.tell() != initial_a or stream_b.tell() != initial_b:
        msg = f"reset_stream_pointers failed to rewind to exact initial offsets ({initial_a}, {initial_b})"
        raise AssertionError(msg)


async def _fuzz_run_async_retries(fdp: atheris.FuzzedDataProvider) -> None:
    delay_probe = compute_retry_delay(
        fdp.ConsumeIntInRange(-2, 30),
        fdp.PickValueInList(
            [
                None,
                "0",
                "12.5",
                "NaN",
                "-1",
                "Wed, 21 Oct 2015 07:28:00 GMT",
                fdp.ConsumeUnicodeNoSurrogates(24),
            ]
        ),
        max_delay=5.0,
    )
    if not math.isfinite(delay_probe) or delay_probe < 0.0 or delay_probe > 5.0:
        msg = f"compute_retry_delay produced out-of-range delay: {delay_probe!r}"
        raise AssertionError(msg)
    _ = parse_retry_after_http_date(fdp.ConsumeUnicodeNoSurrogates(32), max_delay=5.0)

    httpx2_mod = httpx2
    if httpx2_mod is None:
        return

    raw_retries: Any = True if fdp.ConsumeIntInRange(0, 15) == 0 else fdp.ConsumeIntInRange(-1, 3)
    method = fdp.PickValueInList([*RETRY_ALLOWED_METHODS, "TRACE"])
    statuses = [fdp.PickValueInList([200, 400, 429, 500, 502, 503, 504]) for _ in range(4)]
    call_idx = 0
    stream_buf = io.BytesIO(b"retryable-request-body")
    stream_buf.seek(3)

    async def send_fn() -> Any:
        nonlocal call_idx
        attempt_no = call_idx
        call_idx += 1
        if attempt_no == 0 and fdp.ConsumeBool():
            err_kind = fdp.ConsumeIntInRange(0, 2)
            if err_kind == 0:
                raise httpx2_mod.TimeoutException("fuzzed retry timeout")
            if err_kind == 1:
                raise httpx2_mod.NetworkError("fuzzed retry network error")
            raise httpx2_mod.UnsupportedProtocol("non-retryable protocol error")

        _ = stream_buf.read(4)
        st = statuses[min(attempt_no, len(statuses) - 1)]
        req = httpx2_mod.Request(method if method != "TRACE" else "GET", "https://api.mailjet.com/v3/REST/contact")
        headers = {"Retry-After": "0"} if st in TRANSIENT_STATUS_CODES else {}
        return httpx2_mod.Response(st, headers=headers, json={"Data": []}, request=req)

    try:
        resp = await run_async_with_retries(
            send_fn,
            httpx2_mod,
            method=method,
            url="https://api.mailjet.com/v3/REST/contact",
            raw_retries=raw_retries,
            max_retries_limit=3,
            allowed_methods=RETRY_ALLOWED_METHODS,
            transient_status_codes=TRANSIENT_STATUS_CODES,
            max_delay=0.0,
            data={"stream": stream_buf},
            files=None,
            log=_SILENT_LOGGER,
        )
    except (ValueError, httpx2_mod.TimeoutException, httpx2_mod.NetworkError, httpx2_mod.UnsupportedProtocol):
        return

    if isinstance(raw_retries, bool) or raw_retries < 0:
        msg = f"run_async_with_retries accepted invalid raw_retries={raw_retries!r}"
        raise AssertionError(msg)
    if resp is None:
        msg = "run_async_with_retries returned None"
        raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across AsyncEndpoint.stream(), stream rewind, and async retries."""
    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _loop.run_until_complete(_fuzz_async_stream(fdp))
        elif mode == 1:
            _fuzz_stream_rewind(fdp)
        else:
            _loop.run_until_complete(_fuzz_run_async_retries(fdp))
    except (ValueError, TypeError, ApiError):
        # Expected validation and API error paths under malformed inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_async_pagination_and_retry: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for async pagination and retry resilience."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
