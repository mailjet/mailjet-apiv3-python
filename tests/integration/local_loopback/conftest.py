"""Module-scoped loopback server fixtures for tests/integration/local_loopback."""

from __future__ import annotations

from collections.abc import Generator
from typing import Any

import pytest

from tests.integration.local_loopback._servers import (
    _WebhookHTTPServer,
    run_builders_tls_server,
    run_loopback_servers,
    run_webhook_server,
)


@pytest.fixture(scope="module")
def loopback_servers(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start isolated loopback TLS 1.2+ HTTPS and plain HTTP servers with valid, untrusted, and combined PEMs."""
    cert_dir = tmp_path_factory.mktemp("transport_tls")
    with run_loopback_servers(cert_dir) as servers:
        yield servers


@pytest.fixture(scope="module")
def builders_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback HTTPS TLS 1.2+ server for builders and security integration."""
    cert_dir = tmp_path_factory.mktemp("tls_builders_security")
    with run_builders_tls_server(cert_dir) as server_info:
        yield server_info


@pytest.fixture(scope="module")
def webhook_server() -> Generator[tuple[str, _WebhookHTTPServer], None, None]:
    """Start an isolated loopback HTTP webhook receiver for sync and async POST checks."""
    with run_webhook_server() as server_info:
        yield server_info
