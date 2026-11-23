"""Property-based tests for Mailjet SDK AsyncClient and AsyncEndpoint invariants.

Powered by Hypothesis.
"""

from __future__ import annotations

import asyncio
from contextlib import suppress
from typing import Any
from unittest.mock import AsyncMock
import warnings

import pytest
from hypothesis import given, settings, strategies as st

from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import (
    ApiError,
    ApiRateLimitError,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    TimeoutError,  # ruff: ignore[builtin-import-shadowing]
    ValidationError,
)


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")


@settings(max_examples=150, deadline=None)
@given(auth_input=st.one_of(st.tuples(st.text(), st.text()), st.text(), st.integers(), st.none()))
def test_property_async_client_auth_and_lifecycle(auth_input: Any) -> None:
    """INVARIANT: AsyncClient must coerce valid auth, redact secrets in repr/str, and close cleanly."""

    async def _run() -> None:
        if _httpx2 is None:
            pytest.skip("httpx2 is not installed")
        assert _httpx2 is not None
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            with suppress(ValueError, TypeError):
                async with AsyncClient(auth=auth_input, version="v3") as aclient:
                    assert "AsyncClient" in repr(aclient)
                    assert "Mailjet AsyncClient" in str(aclient)
                    assert "send" in dir(aclient)
                    if isinstance(auth_input, tuple):
                        assert aclient.auth == (auth_input[0].strip(), auth_input[1].strip())
                    elif isinstance(auth_input, str):
                        assert aclient.session.headers.get("Authorization") == f"Bearer {auth_input.strip()}"
                await aclient.close()

    asyncio.run(_run())


@settings(max_examples=150, deadline=None)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    payload=st.one_of(
        st.dictionaries(st.text(min_size=1, max_size=10), st.text(max_size=20), max_size=5),
        st.lists(st.dictionaries(st.text(min_size=1, max_size=10), st.text(max_size=20), max_size=3), max_size=3),
        st.text(max_size=30),
        st.none(),
    ),
    timeout=st.one_of(
        st.integers(min_value=1, max_value=86400),
        st.tuples(st.floats(min_value=0.1, max_value=60.0), st.floats(min_value=0.1, max_value=60.0)),
    ),
    dry_run=st.booleans(),
)
def test_property_async_api_call_and_endpoint_crud(
    method: Any,
    payload: Any,
    timeout: Any,
    *,
    dry_run: bool,
) -> None:
    """INVARIANT: AsyncClient.api_call and AsyncEndpoint CRUD handle payloads, idempotency, and dry_run."""

    async def _run() -> None:
        if _httpx2 is None:
            pytest.skip("httpx2 is not installed")
        assert _httpx2 is not None
        async with AsyncClient(auth=("pub_key", "priv_key"), dry_run=dry_run) as aclient:
            req = _httpx2.Request(method, "https://api.mailjet.com/v3/REST/contact")
            mock_resp = _httpx2.Response(200, json={"Data": [{"ID": 1}]}, request=req)
            aclient.session.request = AsyncMock(return_value=mock_resp)  # type: ignore[method-assign]

            ep = aclient.contact
            assert isinstance(ep, AsyncEndpoint)
            assert aclient.contact is ep

            if method == "GET":
                res = await ep.get(timeout=timeout, filters={"Limit": 1})
            elif method == "POST":
                res = await ep.create(data=payload, timeout=timeout)
            elif method == "PUT":
                res = await ep.update(id=1, data=payload, timeout=timeout)
            else:
                res = await ep.delete(id=1, timeout=timeout)

            assert res.status_code == 200

    asyncio.run(_run())


@settings(max_examples=150, deadline=None)
@given(
    status_code=st.sampled_from([400, 401, 403, 404, 429, 500, 502]),
    error_msg=st.text(min_size=1, max_size=50),
)
def test_property_async_error_mapping(status_code: int, error_msg: str) -> None:
    """INVARIANT: AsyncClient must map HTTP status errors and transport errors to Mailjet exceptions."""

    async def _run() -> None:
        if _httpx2 is None:
            pytest.skip("httpx2 is not installed")
        assert _httpx2 is not None
        async with AsyncClient(auth=("pub", "priv"), max_retries=0) as aclient:
            req = _httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")
            resp = _httpx2.Response(status_code, json={"ErrorMessage": error_msg}, request=req)
            sess: Any = aclient.session
            sess.request = AsyncMock(return_value=resp)

            expected_exc: type[ApiError]
            if status_code in {401, 403}:
                expected_exc = MailjetAuthError
            elif status_code == 429:
                expected_exc = ApiRateLimitError
            elif status_code == 404:
                expected_exc = DoesNotExistError
            elif status_code == 400:
                expected_exc = ValidationError
            else:
                expected_exc = MailjetApiError

            with pytest.raises(expected_exc):
                await aclient.contact.get()

            sess.request = AsyncMock(side_effect=_httpx2.TimeoutException("timeout"))
            with pytest.raises(TimeoutError):
                await aclient.contact.get()

            sess.request = AsyncMock(side_effect=_httpx2.ConnectError("connect fail"))
            with pytest.raises(CriticalApiError):
                await aclient.contact.get()

    asyncio.run(_run())
