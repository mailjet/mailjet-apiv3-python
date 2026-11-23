"""Stateful Hypothesis property tests for AsyncClient lifecycle and CRUD invariants."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.errors import MailjetApiError


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")


class AsyncClientStateMachine(RuleBasedStateMachine):
    """Verify AsyncClient session lifecycle, pool healing, CRUD/stream, and ping invariants."""

    def __init__(self) -> None:
        """Initialize the state machine instance."""
        super().__init__()
        self._loop: asyncio.AbstractEventLoop | None = None
        self.client: AsyncClient | None = None
        self.closed = False
        self.next_status = 200
        self.observed_requests: list[tuple[str, str, str]] = []

    @initialize()
    def init_client(self) -> None:
        """Create a dedicated event loop, MockTransport, and AsyncClient."""
        assert _httpx2 is not None
        httpx2_mod = _httpx2
        self._loop = asyncio.new_event_loop()
        self.closed = False
        self.next_status = 200
        self.observed_requests.clear()

        def handler(request: Any) -> Any:
            auth_hdr = str(request.headers.get("Authorization", ""))
            self.observed_requests.append((request.method, request.url.path, auth_hdr))
            status = self.next_status
            if status >= 400:
                return httpx2_mod.Response(status, json={"ErrorMessage": f"status-{status}"})
            return httpx2_mod.Response(status, json={"Data": [{"ID": 1}], "Count": 1, "Total": 1})

        self.client = AsyncClient(
            auth=("state_pub", "state_priv"),
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        )

    def _run(self, coro: Any) -> Any:
        assert self._loop is not None
        return self._loop.run_until_complete(coro)

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(contact_id=st.integers(min_value=1, max_value=500))
    def get_contact(self, contact_id: int) -> None:
        """Execute an authenticated GET call against the contact endpoint."""
        assert self.client is not None
        self.next_status = 200
        resp = self._run(self.client.contact.get(id=contact_id))
        assert resp.status_code == 200
        assert self.observed_requests[-1][0] == "GET"
        assert self.observed_requests[-1][2].startswith("Basic ")

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(email=st.emails())
    def create_contact(self, email: str) -> None:
        """Execute an authenticated POST create call."""
        assert self.client is not None
        self.next_status = 201
        resp = self._run(self.client.contact.create(data={"Email": email}))
        assert resp.status_code == 201
        assert self.observed_requests[-1][0] == "POST"

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(contact_id=st.integers(min_value=1, max_value=500), name=st.text(min_size=1, max_size=24))
    def update_contact(self, contact_id: int, name: str) -> None:
        """Execute an authenticated PUT update call."""
        assert self.client is not None
        self.next_status = 200
        resp = self._run(self.client.contact.update(id=contact_id, data={"Name": name}))
        assert resp.status_code == 200
        assert self.observed_requests[-1][0] == "PUT"

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(contact_id=st.integers(min_value=1, max_value=500))
    def delete_contact(self, contact_id: int) -> None:
        """Execute an authenticated DELETE call."""
        assert self.client is not None
        self.next_status = 204
        resp = self._run(self.client.contact.delete(id=contact_id))
        assert resp.status_code == 204
        assert self.observed_requests[-1][0] == "DELETE"

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule()
    def stream_contacts(self) -> None:
        """Consume bounded items from AsyncEndpoint.stream()."""
        assert self.client is not None
        self.next_status = 200

        async def _collect() -> list[dict[str, Any]]:
            assert self.client is not None
            return [item async for item in self.client.contact.stream(chunk_size=10, max_items=1)]

        items = self._run(_collect())
        assert len(items) <= 1

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(status=st.sampled_from([200, 401, 500]))
    def ping_api(self, status: int) -> None:
        """Verify AsyncClient.ping() maps 200 -> True and HTTP errors -> False."""
        assert self.client is not None
        self.next_status = status
        ok = self._run(self.client.ping())
        assert ok is (status < 400)

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule()
    def trigger_api_error(self) -> None:
        """Verify 404 responses raise MailjetApiError without breaking client state."""
        assert self.client is not None
        self.next_status = 404
        with pytest.raises(MailjetApiError):
            self._run(self.client.contact.get(id=1))

    @precondition(lambda self: not self.closed and self.client is not None and self.client._session is not None)  # ruff: ignore[private-member-access]
    @rule()
    def close_underlying_pool(self) -> None:
        """Close the inner httpx2 session directly and verify self-healing rebuilds an open pool."""
        assert self.client is not None
        sess = self.client.session
        self._run(sess.aclose())
        assert sess.is_closed
        healed = self.client.session
        assert healed is not sess
        assert not healed.is_closed

    @rule()
    def aclose_idempotent(self) -> None:
        """Close AsyncClient idempotently."""
        if self.client is not None:
            self._run(self.client.aclose())
            self.closed = True

    @rule()
    def reopen_context(self) -> None:
        """Re-enter async context manager so a closed client becomes active again."""
        if self.client is not None:
            entered = self._run(self.client.__aenter__())
            assert entered is self.client
            self.closed = False

    @invariant()
    def check_session_invariants(self) -> None:
        """Ensure _closed and _session remain consistent across arbitrary operation sequences."""
        if self.client is None:
            return
        if self.closed:
            assert self.client._closed is True  # ruff: ignore[private-member-access]
            assert self.client._session is None  # ruff: ignore[private-member-access]
        else:
            assert self.client._closed is False  # ruff: ignore[private-member-access]

    def teardown(self) -> None:
        """Clean up async session and event loop cleanly at end of example."""
        if self._loop is not None:
            if self.client is not None:
                self._run(self.client.aclose())
            self._loop.close()
            self._loop = None


TestAsyncClientStateful = AsyncClientStateMachine.TestCase
TestAsyncClientStateful.settings = settings(max_examples=35, stateful_step_count=12, deadline=None)
