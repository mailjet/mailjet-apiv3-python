#!/usr/bin/env python3
"""Atheris fuzzing target for all 89 ROUTE_MAP routes, sync/async differential parity, MockMailjetClient, and signed webhook timestamps."""

from __future__ import annotations

import asyncio
import gc
import hashlib
import hmac
import logging
import sys
import time
import warnings
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import AsyncClient, Client, _httpx2 as httpx2
    from mailjet_rest.errors import ApiError, ValidationError
    from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP
    from mailjet_rest.testing import MockMailjetClient
    from mailjet_rest.utils.routing import build_endpoint_headers, cast_query_param
    from mailjet_rest.webhooks import verify_webhook_signature


_loop = asyncio.new_event_loop()
_ROUTE_KEYS = tuple(sorted(ROUTE_MAP.keys()))
_sync_client = Client(auth=("fuzz_pub_key", "fuzz_priv_key"), max_retries=0)
_async_client: AsyncClient | None = (
    AsyncClient(auth=("fuzz_pub_key", "fuzz_priv_key"), max_retries=0) if httpx2 is not None else None
)
_exec_count = 0


def _fuzz_routes_and_differential_parity(fdp: atheris.FuzzedDataProvider) -> None:
    dynamic_routes = ("contactslist_csvdata", "batchjob_csverror", "data_contacts_sync", "customResource_actionOne")
    if fdp.ConsumeBool():
        ep_name = fdp.PickValueInList(_ROUTE_KEYS)
    else:
        ep_name = fdp.PickValueInList(dynamic_routes)

    sync_ep = getattr(_sync_client, ep_name)
    id_val: Any = (
        fdp.ConsumeIntInRange(1, 99999)
        if fdp.ConsumeBool()
        else (fdp.ConsumeUnicodeNoSurrogates(12) if fdp.ConsumeBool() else None)
    )
    action_id: Any = fdp.ConsumeIntInRange(1, 999) if fdp.ConsumeBool() else None
    header_variants: dict[str, str | None] = {}
    if fdp.ConsumeBool():
        ct_key = fdp.PickValueInList(["content-type", "Content-Type", "CONTENT-TYPE"])
        header_variants[ct_key] = fdp.PickValueInList(
            ["application/problem+json", "application/merge-patch+json", "text/plain"]
        )
    if fdp.ConsumeBool():
        header_variants[fdp.ConsumeUnicodeNoSurrogates(12) or "X-Fuzz"] = fdp.ConsumeUnicodeNoSurrogates(24)

    payload = {fdp.ConsumeUnicodeNoSurrogates(8) or "k": fdp.ConsumeUnicodeNoSurrogates(16)}
    extra_kwargs: dict[str, Any] = {}
    if fdp.ConsumeBool():
        extra_kwargs["ensure_ascii"] = fdp.ConsumeBool()

    built_hdrs = build_endpoint_headers(ep_name.lower(), header_variants or None)
    ct_keys = [k for k in built_hdrs if k.lower() == "content-type"]
    if len(ct_keys) != 1:
        msg = f"Duplicate or missing Content-Type header keys for {ep_name}: {ct_keys!r}"
        raise AssertionError(msg)

    sync_err: type[BaseException] | None = None
    sync_args: tuple[Any, Any, Any] | None = None
    try:
        sync_args = sync_ep._prepare_call_args(id_val, payload, action_id, header_variants or None, dict(extra_kwargs))
    except Exception as exc:
        # Capture exception type to verify sync/async parity across all 89 routes.
        sync_err = type(exc)

    if _async_client is not None:
        async_ep = getattr(_async_client, ep_name)
        async_err: type[BaseException] | None = None
        async_args: tuple[Any, Any, Any] | None = None
        try:
            async_args = async_ep._prepare_call_args(
                id_val, payload, action_id, header_variants or None, dict(extra_kwargs)
            )
        except Exception as exc:
            # Capture exception type to verify sync/async parity across all 89 routes.
            async_err = type(exc)

        if sync_err != async_err or sync_args != async_args:
            msg = f"Sync vs AsyncEndpoint parity mismatch on route {ep_name!r}"
            raise AssertionError(msg)

    _ = cast_query_param(fdp.PickValueInList([True, 0, 1.5, [], (), set(), "s"]), fdp.ConsumeUnicodeNoSurrogates(12))
    try:
        cast_query_param(0, True)
    except TypeError:
        # Expected TypeError blocking bool coercion into numeric query param.
        pass
    else:
        msg = "cast_query_param(0, True) must raise TypeError"
        raise AssertionError(msg)
    _ = DEPRECATION_ADVISORY.get(ep_name.lower())


async def _fuzz_mock_sync_async_parity(fdp: atheris.FuzzedDataProvider) -> None:
    status = fdp.PickValueInList([200, 201, 204, 400, 401, 403, 404, 429, 500, 503])
    ep_name = fdp.PickValueInList(["send_v31", "contact", "template", fdp.ConsumeUnicodeNoSurrogates(16) or "sender"])
    if ep_name.startswith("_"):
        return

    sync_mock = MockMailjetClient(default_status=status)
    async_mock = MockMailjetClient(default_status=status)
    op = fdp.ConsumeIntInRange(0, 5)
    res_id: Any = fdp.ConsumeIntInRange(1, 500)
    payload = {"CustomID": fdp.ConsumeUnicodeNoSurrogates(20), "Email": "fuzz@example.com"}
    filters = {"Limit": fdp.ConsumeIntInRange(1, 50)}

    if op == 0:
        r_sync = getattr(sync_mock, ep_name).get(id=res_id, filters=filters)
        r_async = await getattr(async_mock, ep_name).get(id=res_id, filters=filters)
    elif op == 1:
        r_sync = getattr(sync_mock, ep_name).create(data=payload)
        r_async = await getattr(async_mock, ep_name).create(data=payload)
    elif op == 2:
        r_sync = getattr(sync_mock, ep_name).update(id=res_id, data=payload)
        r_async = await getattr(async_mock, ep_name).update(id=res_id, data=payload)
    elif op == 3:
        r_sync = getattr(sync_mock, ep_name).delete(id=res_id)
        r_async = await getattr(async_mock, ep_name).delete(id=res_id)
    elif op == 4:
        _ = list(getattr(sync_mock, ep_name).stream(filters=filters, chunk_size=10))
        _ = [item async for item in getattr(async_mock, ep_name).stream(filters=filters, chunk_size=10)]
        r_sync = None
        r_async = None
    else:
        ping_sync = bool(sync_mock.ping())
        ping_async = await async_mock.ping()
        if ping_sync != ping_async:
            msg = "MockMailjetClient sync/async ping() diverged"
            raise AssertionError(msg)
        return

    if sync_mock.sent_requests != async_mock.sent_requests:
        msg = "MockMailjetClient sync/async sent_requests parity diverged"
        raise AssertionError(msg)

    if r_sync is not None and r_async is not None and status >= 400:
        _assert_mock_error_raised(r_sync, status)
        _assert_mock_error_raised(r_async, status)


def _assert_mock_error_raised(resp: Any, status: int) -> None:
    try:
        resp.raise_for_status()
    except ApiError:
        # Expected HTTP error mapping when MockResponse status >= 400.
        pass
    else:
        msg = f"MockResponse.raise_for_status() missed HTTP {status}"
        raise AssertionError(msg)


def _fuzz_signed_timestamp_webhooks(fdp: atheris.FuzzedDataProvider) -> None:
    payload = fdp.ConsumeBytes(64)
    raw_secret = fdp.ConsumeUnicodeNoSurrogates(24)
    fallback_hmac = "whsec_fuzz_fallback"  # pragma: allowlist secret
    secret = raw_secret if raw_secret.strip() else fallback_hmac
    now_ts = int(time.time())
    offset = fdp.ConsumeIntInRange(-10, 10)
    ts = now_ts + offset
    max_age = fdp.ConsumeIntInRange(20, 300)

    try:
        verify_webhook_signature(payload, "0" * 64, secret, timestamp_unix=None, signed_timestamp=True)
    except ValueError:
        # Expected rejection when signed_timestamp=True without timestamp_unix.
        pass
    else:
        msg = "verify_webhook_signature allowed signed_timestamp=True with timestamp_unix=None"
        raise AssertionError(msg)

    signed_input = f"{ts}.".encode("ascii") + payload
    digest = hmac.new(secret.encode("utf-8"), signed_input, hashlib.sha256).hexdigest()
    if not verify_webhook_signature(
        payload,
        f"sha256={digest}",
        secret,
        timestamp_unix=ts,
        max_age_seconds=max_age,
        signed_timestamp=True,
    ):
        msg = "Valid signed-timestamp HMAC-SHA256 webhook signature was rejected"
        raise AssertionError(msg)

    tampered_ts = ts + fdp.PickValueInList([-3, -1, 1, 3])
    if verify_webhook_signature(
        payload,
        digest,
        secret,
        timestamp_unix=tampered_ts,
        max_age_seconds=max_age,
        signed_timestamp=True,
    ):
        msg = "Tampered timestamp passed signed_timestamp=True MAC verification"
        raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across 89-route sync/async parity, MockMailjetClient, and webhooks."""
    global _exec_count
    _exec_count += 1
    if _exec_count % 1000 == 0:
        _sync_client._endpoint_cache.clear()  # ruff: ignore[private-member-access]
        if _async_client is not None:
            _async_client._endpoint_cache.clear()  # ruff: ignore[private-member-access]
        gc.collect()

    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _fuzz_routes_and_differential_parity(fdp)
        elif mode == 1:
            _loop.run_until_complete(_fuzz_mock_sync_async_parity(fdp))
        else:
            _fuzz_signed_timestamp_webhooks(fdp)
    except (ValueError, TypeError, AttributeError, ValidationError, ApiError):
        # Expected rejections on malformed fuzzed routing, header, or webhook inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_openapi_routes_and_mock_parity: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for OpenAPI routes and sync/async mock parity."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
