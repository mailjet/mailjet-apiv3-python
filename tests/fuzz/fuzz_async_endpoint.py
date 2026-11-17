#!/usr/bin/env python3
"""Atheris fuzzing target for Mailjet AsyncEndpoint routing, CRUD, and async stream pagination."""

from __future__ import annotations

import asyncio
import logging
import sys
import warnings
from typing import Any
from unittest.mock import MagicMock

import atheris

try:
    import httpx2
except ImportError:
    httpx2 = None  # type: ignore[assignment]


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import AsyncClient
    from mailjet_rest.endpoint import AsyncEndpoint
    from mailjet_rest.errors import ApiError, MailjetApiError, ValidationError
    from mailjet_rest.routes import ROUTE_MAP


_loop = asyncio.new_event_loop()
_ROUTE_KEYS = list(ROUTE_MAP.keys())


async def _fuzz_async_endpoint(fdp: atheris.FuzzedDataProvider) -> None:
    mock_client = MagicMock(spec=AsyncClient)
    mock_client.config = MagicMock()
    mock_client.config.version = fdp.PickValueInList(["v3", "v3.1", "v1"])
    mock_client.config.api_url = "https://api.mailjet.com/"

    pages_remaining = fdp.ConsumeIntInRange(0, 3)

    async def mock_api_call(*_args: Any, **_kwargs: Any) -> Any:
        nonlocal pages_remaining
        if httpx2 is not None:
            req = httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")
            if pages_remaining > 0:
                pages_remaining -= 1
                return httpx2.Response(200, json={"Data": [{"ID": pages_remaining}]}, request=req)
            return httpx2.Response(200, json={"Data": []}, request=req)

        m = MagicMock(status_code=200)
        if pages_remaining > 0:
            pages_remaining -= 1
            m.json.return_value = {"Data": [{"ID": pages_remaining}]}
        else:
            m.json.return_value = {"Data": []}
        return m

    mock_client.api_call = mock_api_call

    route_choices = [
        *_ROUTE_KEYS[:10],
        "contactslist_csvdata",
        "batchjob_csverror",
        "data_custom_route",
        "customResource_camelAction",
        fdp.ConsumeUnicodeNoSurrogates(20),
    ]
    name = fdp.PickValueInList(route_choices)
    endpoint = AsyncEndpoint(client=mock_client, name=name)

    id_choice = fdp.ConsumeIntInRange(0, 2)
    id_val: int | str | None = (
        None
        if id_choice == 0
        else (fdp.ConsumeIntInRange(1, 9999) if id_choice == 1 else fdp.ConsumeUnicodeNoSurrogates(15))
    )
    action_id: int | str | None = fdp.ConsumeUnicodeNoSurrogates(12) if fdp.ConsumeBool() else None

    filters: dict[str, Any] = {}
    if fdp.ConsumeBool():
        filters["limit"] = fdp.ConsumeIntInRange(-10, 2000)
    if fdp.ConsumeBool():
        filters["offset"] = (
            [str(fdp.ConsumeIntInRange(0, 500))] if fdp.ConsumeBool() else fdp.ConsumeUnicodeNoSurrogates(8)
        )

    headers: dict[str, str | None] = {}
    if fdp.ConsumeBool():
        for _ in range(fdp.ConsumeIntInRange(1, 4)):
            headers[fdp.ConsumeUnicodeNoSurrogates(12)] = fdp.ConsumeUnicodeNoSurrogates(24)

    if fdp.ConsumeBool():
        chunk_size = fdp.ConsumeIntInRange(-5, 1500)
        count = 0
        async for _ in endpoint.stream(
            id=id_val,
            action_id=action_id,
            filters=filters,
            chunk_size=chunk_size,
        ):
            count += 1
            if count > 5:
                break

    payload = {fdp.ConsumeUnicodeNoSurrogates(8): fdp.ConsumeUnicodeNoSurrogates(16)}
    ensure_ascii: bool | None = None
    if fdp.ConsumeBool():
        ensure_ascii = fdp.ConsumeBool()
    data_encoding = "utf-8" if fdp.ConsumeBool() else None

    op = fdp.ConsumeIntInRange(0, 3)
    if op == 0:
        await endpoint.get(id=id_val, filters=filters, action_id=action_id, headers=headers)
    elif op == 1:
        await endpoint.create(
            data=payload,
            id=id_val,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
        )
    elif op == 2:
        await endpoint.update(
            id=id_val or 1,
            data=payload,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
        )
    else:
        await endpoint.delete(id=id_val or 1, action_id=action_id)


def TestOneInput(data: bytes) -> None:
    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    try:
        _loop.run_until_complete(_fuzz_async_endpoint(fdp))
    except (ValueError, TypeError, AttributeError, KeyError, ValidationError, MailjetApiError, ApiError):
        return  # Expected SDK validation and routing rejections on malformed fuzz input.
    except Exception as e:
        msg = f"UNHANDLED CRASH in AsyncEndpoint fuzzer: {type(e).__name__} - {e}"
        raise RuntimeError(msg) from e


if __name__ == "__main__":
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()
