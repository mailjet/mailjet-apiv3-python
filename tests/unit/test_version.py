from __future__ import annotations

import sys
from contextlib import suppress
from unittest.mock import patch

from mailjet_rest.utils.version import get_version


def test_version_length_equal_three() -> None:
    """Verifies standard version fetching returns a properly formatted string."""
    version = get_version()
    if version:
        assert len(version.split(".")) >= 3


def test_get_version_is_none() -> None:
    """Simulates an environment where version retrieval dependencies fail."""
    with patch.dict(
        sys.modules,
        {"pkg_resources": None, "importlib.metadata": None, "mailjet_rest": None},
    ):
        version = get_version()
        assert version is None


def test_get_version() -> None:
    assert get_version() is not None


def test_get_version_raises_exception() -> None:
    """Forces the version parser to hit its fallback exception blocks (ValueError, ImportError, etc.)."""
    # By forcing parser-related exceptions, verify get_version gracefully falls back.
    with patch(
        "mailjet_rest.utils.version.open",
        side_effect=ValueError("Forced ValueError for coverage"),
    ):
        with patch.dict(
            sys.modules, {"pkg_resources": None, "importlib.metadata": None}
        ):
            assert get_version() is None

    with patch(
        "mailjet_rest.utils.version.open",
        side_effect=ImportError("Forced ImportError for coverage"),
    ):
        with patch.dict(
            sys.modules, {"pkg_resources": None, "importlib.metadata": None}
        ):
            assert get_version() is None
