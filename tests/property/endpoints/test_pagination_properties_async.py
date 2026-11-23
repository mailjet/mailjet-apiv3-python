"""Property-based tests for asynchronous Mailjet SDK Pagination and Streaming.

Powered by Hypothesis.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from hypothesis import given, settings, strategies as st

from mailjet_rest.client import AsyncClient, _httpx2


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")


@settings(max_examples=150, deadline=None)
@given(total_items=st.integers(min_value=0, max_value=500), chunk_size=st.integers(min_value=1, max_value=200))
def test_property_async_pagination_math(total_items: int, chunk_size: int) -> None:
    """INVARIANT: AsyncEndpoint.stream() must yield exact items sequentially across page boundaries."""

    async def _run() -> None:
        if _httpx2 is None:
            pytest.skip("httpx2 is not installed")
        assert _httpx2 is not None
        httpx2_mod = _httpx2
        async with AsyncClient(auth=("pub", "priv"), max_retries=0) as aclient:
            database = [{"ID": i} for i in range(total_items)]
            req = httpx2_mod.Request("GET", "https://api.mailjet.com/v3/REST/contact")

            async def mock_request(*_args: Any, **kwargs: Any) -> Any:
                params = kwargs.get("params") or {}
                offset = params.get("Offset", 0)
                limit = params.get("Limit", chunk_size)
                page_data = database[offset : offset + limit]
                return httpx2_mod.Response(200, json={"Data": page_data}, request=req)

            aclient.session.request = mock_request  # type: ignore[method-assign]
            items = [item async for item in aclient.contact.stream(chunk_size=chunk_size)]
            assert len(items) == total_items
            for idx, item in enumerate(items):
                assert item["ID"] == idx

    asyncio.run(_run())
