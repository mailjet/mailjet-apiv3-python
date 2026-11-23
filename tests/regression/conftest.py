"""Shared repository paths and fixtures for tests/regression scope packages."""

from __future__ import annotations

from collections.abc import Generator
from pathlib import Path

import pytest

from mailjet_rest.client import Client


REPO_ROOT: Path = Path(__file__).resolve().parents[2]
if not (REPO_ROOT / "pyproject.toml").is_file():
    msg = f"Expected repository root with pyproject.toml at {REPO_ROOT}"
    raise RuntimeError(msg)

SAMPLES_DIR: Path = REPO_ROOT / "samples"
FUZZER_DICT_PATH: Path = REPO_ROOT / "tests" / "fuzz" / "fuzzer.dict"


@pytest.fixture
def client_v3() -> Generator[Client, None, None]:
    """Provide an offline-ready v3 synchronous Mailjet Client instance for regression tests."""
    with Client(auth=("test_pub", "test_priv"), version="v3") as client:
        yield client
