"""Shared helpers, OpenAPI manifest loader, and loopback TLS cert generator for tests/integration."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any, cast

import pytest


REPO_ROOT: Path = Path(__file__).resolve().parents[2]
MANIFEST_PATH: Path = Path(__file__).resolve().parent / "fixtures" / "openapi_operations_manifest.json"
HTTP_METHODS: tuple[str, ...] = ("get", "post", "put", "patch", "delete")


def load_openapi_manifest() -> dict[str, Any]:
    """Load the standalone vendored OpenAPI + ROUTE_MAP contract manifest."""
    return cast("dict[str, Any]", json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))


def generate_loopback_tls_cert(cert_dir: Path, name: str) -> tuple[Path, Path]:
    """Generate an ephemeral self-signed X.509 cert bound to localhost and 127.0.0.1."""
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary not available for loopback TLS integration test")
    assert openssl is not None
    cert_path = cert_dir / f"{name}.pem"
    key_path = cert_dir / f"{name}.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return cert_path, key_path


def has_live_credentials() -> bool:
    """Return True only when live Mailjet API keys exist in the environment."""
    return "MJ_APIKEY_PUBLIC" in os.environ and "MJ_APIKEY_PRIVATE" in os.environ


def get_live_auth() -> tuple[str, str]:
    """Return live Mailjet (public, private) API key tuple from environment variables."""
    return (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])
