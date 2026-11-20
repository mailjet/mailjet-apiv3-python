"""Pytest fixtures for tests/integration/contracts."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from tests.integration.contracts._server import build_contract_tls_server


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture(scope="module")
def contract_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback TLS 1.2+ server for OpenAPI and 89-route contract checks."""
    yield from build_contract_tls_server(tmp_path_factory)
