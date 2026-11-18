#!/usr/bin/env python3
"""Atheris fuzzing target for Mailjet AsyncClient (httpx2).

Stresses asynchronous request execution, auth coercion, idempotency hashing,
tuple timeout conversion, and httpx2 exception mapping using a persistent event loop.
"""

from __future__ import annotations

import asyncio
import copy
import gc
import logging
import sys
import warnings
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import AsyncClient, _httpx2 as httpx2
    from mailjet_rest.config import Config
    from mailjet_rest.errors import (
        ApiError,
        ApiRateLimitError,
        CriticalApiError,
        DoesNotExistError,
        MailjetApiError,
        MailjetAuthError,
        MailjetNetworkError,
        TimeoutError,  # ruff: ignore[builtin-import-shadowing]
        ValidationError,
    )


_loop = asyncio.new_event_loop()
_exec_count = 0

_base_async_client: AsyncClient | None = (
    AsyncClient(auth=("fuzz_pub_key", "fuzz_priv_key"), max_retries=0) if httpx2 is not None else None
)


async def _fuzz_async_client_iteration(fdp: atheris.FuzzedDataProvider) -> None:
    httpx2_mod = httpx2
    base_client = _base_async_client
    if httpx2_mod is None or base_client is None:
        return

    mode = fdp.ConsumeIntInRange(0, 3)

    if mode == 0:
        auth_kind = fdp.ConsumeIntInRange(0, 2)
        if auth_kind == 0:
            auth_val: Any = fdp.ConsumeUnicodeNoSurrogates(48)
        elif auth_kind == 1:
            auth_val = (fdp.ConsumeUnicodeNoSurrogates(24), fdp.ConsumeUnicodeNoSurrogates(24))
        else:
            auth_val = fdp.ConsumeInt(100)

        try:
            cfg = Config(
                version=fdp.PickValueInList(["v3", "v3.1", "v1", fdp.ConsumeUnicodeNoSurrogates(6)]),
                dry_run=fdp.ConsumeBool(),
                max_retries=0,
            )
            aclient = AsyncClient(auth=auth_val, config=cfg)
            _ = repr(aclient)
            _ = str(aclient)
            _ = copy.copy(aclient)
            await aclient.aclose()
        except (ValueError, TypeError):
            return
        return

    if mode == 1:
        method = fdp.PickValueInList(["GET", "POST", "PUT", "PATCH", "DELETE"])
        status_code = fdp.PickValueInList([200, 201, 202, 204, 400, 401, 403, 404, 429, 500, 503])
        fault_mode = fdp.ConsumeIntInRange(0, 4)

        async def mock_httpx2_request(**kwargs: Any) -> Any:
            req = httpx2_mod.Request(kwargs.get("method", "GET"), kwargs.get("url", "https://api.mailjet.com/v3/send"))
            if fault_mode == 1:
                raise httpx2_mod.TimeoutException("Fuzzed async timeout")
            if fault_mode == 2:
                raise httpx2_mod.ConnectError("Fuzzed async connection drop")
            if fault_mode == 3:
                raise httpx2_mod.HTTPError("Fuzzed generic httpx2 error")

            body_choice = fdp.ConsumeIntInRange(0, 2)
            if body_choice == 0:
                return httpx2_mod.Response(
                    status_code,
                    json={"ErrorMessage": fdp.ConsumeUnicodeNoSurrogates(40), "Data": [{"ID": 1}]},
                    request=req,
                )
            if body_choice == 1:
                return httpx2_mod.Response(
                    status_code,
                    json={"Messages": [{"Errors": [{"ErrorMessage": fdp.ConsumeUnicodeNoSurrogates(40)}]}]},
                    request=req,
                )
            return httpx2_mod.Response(status_code, text=fdp.ConsumeUnicodeNoSurrogates(64), request=req)

        sess1: Any = base_client.session
        sess1.request = mock_httpx2_request
        base_client.config.dry_run = fdp.ConsumeBool()

        headers: dict[str, str | None] = {
            fdp.ConsumeUnicodeNoSurrogates(16) or "X-Fuzz": fdp.ConsumeUnicodeNoSurrogates(32),
            "Content-Type": "application/json" if fdp.ConsumeBool() else "text/plain",
        }
        payload: Any = (
            {
                "CustomID": fdp.ConsumeUnicodeNoSurrogates(24),
                fdp.ConsumeUnicodeNoSurrogates(12): fdp.ConsumeUnicodeNoSurrogates(24),
            }
            if fdp.ConsumeBool()
            else fdp.ConsumeUnicodeNoSurrogates(48)
        )
        timeout: Any = (
            (fdp.ConsumeFloatInRange(0.1, 30.0), fdp.ConsumeFloatInRange(0.1, 30.0))
            if fdp.ConsumeBool()
            else fdp.ConsumeFloat()
        )

        try:
            await base_client.api_call(
                method=method,
                url="https://api.mailjet.com/v3/REST/contact",
                filters={"Limit": fdp.ConsumeIntInRange(1, 100), "NoneKey": None},
                data=payload,
                headers=headers,
                timeout=timeout,
                verify=fdp.ConsumeBool(),
            )
        except (
            ValueError,
            TypeError,
            TimeoutError,
            CriticalApiError,
            MailjetAuthError,
            ApiRateLimitError,
            DoesNotExistError,
            ValidationError,
            MailjetApiError,
            MailjetNetworkError,
            ApiError,
        ):
            return
        return

    if mode == 2:
        try:
            ep_name = fdp.ConsumeUnicodeNoSurrogates(24)
            ep = getattr(base_client, ep_name)
            _ = repr(ep)
            _ = ep._build_url(  # ruff: ignore[private-member-access]
                id_val=fdp.ConsumeUnicodeNoSurrogates(12) if fdp.ConsumeBool() else None,
                action_id=fdp.ConsumeUnicodeNoSurrogates(12) if fdp.ConsumeBool() else None,
            )
            _ = dir(base_client)
        except (AttributeError, ValueError, TypeError):
            return
        return

    # Mode 3: Concurrent fan-out (asyncio.gather), patch, and ping resilience
    n_tasks = fdp.ConsumeIntInRange(2, 6)

    async def concurrent_mock(**kwargs: Any) -> Any:
        req = httpx2_mod.Request(
            kwargs.get("method", "GET"), kwargs.get("url", "https://api.mailjet.com/v3/REST/contact")
        )
        return httpx2_mod.Response(200, json={"Data": [{"ID": 1}]}, request=req)

    sess3: Any = base_client.session
    sess3.request = concurrent_mock
    base_client.config.dry_run = False
    try:
        tasks: list[Any] = [
            *(base_client.contact.get(id=i) for i in range(n_tasks)),
            base_client.contact.patch(id=1, data={"Name": fdp.ConsumeUnicodeNoSurrogates(16)}),
            base_client.ping(),
        ]
        await asyncio.gather(*tasks, return_exceptions=True)
    except (ValueError, TypeError, ApiError):
        return


def TestOneInput(data: bytes) -> None:
    global _exec_count
    _exec_count += 1

    if _exec_count % 1000 == 0 and _base_async_client is not None:
        _base_async_client._endpoint_cache.clear()  # ruff: ignore[private-member-access]
        gc.collect()

    if len(data) < 8:
        return

    fdp = atheris.FuzzedDataProvider(data)
    try:
        _loop.run_until_complete(_fuzz_async_client_iteration(fdp))
    except RecursionError as e:
        msg = "CRITICAL: RecursionError in AsyncClient!"
        raise RuntimeError(msg) from e
    except Exception as e:
        msg = f"UNHANDLED CRASH in AsyncClient fuzzer: {type(e).__name__} - {e}"
        raise RuntimeError(msg) from e


def main() -> None:
    """Run Atheris fuzzing loop for AsyncClient."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
