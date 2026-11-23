"""Stateful Hypothesis property tests for synchronous Client lifecycle and CRUD invariants."""

from __future__ import annotations

import json
from typing import Any
from unittest.mock import patch
from urllib.parse import urlparse

import pytest
import requests
from hypothesis import settings, strategies as st
from hypothesis.stateful import RuleBasedStateMachine, initialize, invariant, precondition, rule

from mailjet_rest.client import Client
from mailjet_rest.errors import MailjetApiError


class ClientStateMachine(RuleBasedStateMachine):
    """Verify synchronous Client session lifecycle, CRUD/stream, and ping invariants."""

    def __init__(self) -> None:
        """Initialize the state machine instance."""
        super().__init__()
        self.client: Client | None = None
        self.closed = False
        self.next_status = 200
        self.observed_requests: list[tuple[str, str, bool]] = []
        self._request_patcher: Any = None

    def _fake_request(
        self,
        session_self: requests.Session,
        method: str,
        url: str,
        **kwargs: Any,
    ) -> requests.Response:
        """Return a deterministic fake requests.Response without hitting the network."""
        has_auth = session_self.auth is not None
        self.observed_requests.append((method, urlparse(url).path, has_auth))
        status = self.next_status

        resp = requests.Response()
        resp.status_code = status
        resp.url = url
        resp.encoding = "utf-8"
        resp.headers["Content-Type"] = "application/json"

        if status >= 400:
            body: dict[str, Any] = {"ErrorMessage": f"status-{status}"}
            resp._content = json.dumps(body).encode("utf-8")
        elif status == 204:
            resp._content = b""
        else:
            params = kwargs.get("params") or {}
            if "Offset" in params or "Limit" in params:
                offset = int(params.get("Offset", 0))
                limit = int(params.get("Limit", 10))
                page_data = [{"ID": 1}][offset : offset + limit]
                body = {"Data": page_data, "Count": len(page_data), "Total": 1}
            else:
                body = {"Data": [{"ID": 1}], "Count": 1, "Total": 1}
            resp._content = json.dumps(body).encode("utf-8")
        return resp

    @initialize()
    def init_client(self) -> None:
        """Create a synchronous Client with monkeypatched requests.Session.request."""
        if self._request_patcher is not None:
            self._request_patcher.stop()
            self._request_patcher = None

        self.closed = False
        self.next_status = 200
        self.observed_requests.clear()
        self._request_patcher = patch.object(
            requests.Session,
            "request",
            autospec=True,
            side_effect=self._fake_request,
        )
        self._request_patcher.start()
        self.client = Client(auth=("state_pub", "state_priv"), max_retries=0)

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(contact_id=st.integers(min_value=1, max_value=500))
    def get_contact(self, contact_id: int) -> None:
        """Execute an authenticated GET call against the contact endpoint."""
        assert self.client is not None
        self.next_status = 200
        resp = self.client.contact.get(id=contact_id)
        assert resp.status_code == 200
        assert self.observed_requests[-1][0] == "GET"
        assert self.observed_requests[-1][2] is True

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(email=st.emails())
    def create_contact(self, email: str) -> None:
        """Execute an authenticated POST create call."""
        assert self.client is not None
        self.next_status = 201
        resp = self.client.contact.create(data={"Email": email})
        assert resp.status_code == 201
        assert self.observed_requests[-1][0] == "POST"
        assert self.observed_requests[-1][2] is True

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(contact_id=st.integers(min_value=1, max_value=500), name=st.text(min_size=1, max_size=24))
    def update_contact(self, contact_id: int, name: str) -> None:
        """Execute an authenticated PUT update call."""
        assert self.client is not None
        self.next_status = 200
        resp = self.client.contact.update(id=contact_id, data={"Name": name})
        assert resp.status_code == 200
        assert self.observed_requests[-1][0] == "PUT"
        assert self.observed_requests[-1][2] is True

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule()
    def stream_contacts(self) -> None:
        """Consume items from Endpoint.stream(chunk_size=1)."""
        assert self.client is not None
        self.next_status = 200
        ep = self.client.contact
        items = list(ep.stream(chunk_size=1))
        assert items == [{"ID": 1}]

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule(status=st.sampled_from([200, 401, 500]))
    def ping_api(self, status: int) -> None:
        """Verify Client.ping() maps 200 -> True and HTTP errors -> False."""
        assert self.client is not None
        self.next_status = status
        ok = self.client.ping()
        assert ok is (status < 400)

    @precondition(lambda self: not self.closed and self.client is not None)
    @rule()
    def trigger_api_error(self) -> None:
        """Verify 404 responses raise MailjetApiError without breaking client state."""
        assert self.client is not None
        self.next_status = 404
        with pytest.raises(MailjetApiError):
            self.client.contact.get(id=1)

    @rule()
    def close_idempotent(self) -> None:
        """Close Client idempotently."""
        if self.client is not None:
            self.client.close()
            self.client.close()
            self.closed = True

    @rule()
    def reopen_context(self) -> None:
        """Re-enter context manager so a closed client becomes active again."""
        if self.client is not None:
            was_closed = self.closed
            entered = self.client.__enter__()
            assert entered is self.client
            assert self.client._closed is False
            if was_closed:
                assert self.client._session is None
            self.closed = False

    @invariant()
    def check_session_invariants(self) -> None:
        """Ensure _closed and _session remain consistent across arbitrary operation sequences."""
        if self.client is None:
            return
        if self.closed:
            assert self.client._closed is True
            assert self.client._session is None
        else:
            assert self.client._closed is False

    def teardown(self) -> None:
        """Close any open session and stop request monkeypatching cleanly."""
        try:
            if self.client is not None:
                self.client.close()
        finally:
            if self._request_patcher is not None:
                self._request_patcher.stop()
                self._request_patcher = None


TestClientStateful = ClientStateMachine.TestCase
TestClientStateful.settings = settings(max_examples=35, stateful_step_count=12, deadline=None)
