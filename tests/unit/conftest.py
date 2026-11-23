"""Shared offline fixtures for pure unit test suites."""

from __future__ import annotations

import pytest

from mailjet_rest import Client


@pytest.fixture
def client_offline() -> Client:
    """Return an un-networked synchronous Client instance for unit routing/dispatch checks."""
    return Client(auth=("api_key", "api_secret"))
