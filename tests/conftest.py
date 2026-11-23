"""Root pytest hooks preserving process-wide interpreter invariants across suites."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING


if TYPE_CHECKING:
    import pytest


_PREV_DISABLE_LEVEL: dict[int, int] = {}


def pytest_runtest_setup(item: pytest.Item) -> None:
    """Record process-wide logging.disable() threshold before each test executes."""
    _PREV_DISABLE_LEVEL[id(item)] = logging.root.manager.disable


def pytest_runtest_teardown(item: pytest.Item) -> None:
    """Restore logging.disable() threshold if an imported fuzz target mutates it."""
    prev = _PREV_DISABLE_LEVEL.pop(id(item), None)
    if prev is not None and logging.root.manager.disable != prev:
        logging.disable(prev)
