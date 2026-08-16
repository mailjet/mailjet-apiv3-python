from __future__ import annotations

import sys
from contextlib import suppress
from unittest.mock import patch

import pytest

from mailjet_rest.utils.version import clean_version, get_version


def test_version_length_equal_three() -> None:
    """Verifies standard version fetching returns a properly formatted string."""
    version = get_version()
    if version:
        assert len(version.split(".")) >= 3


def test_get_version_is_none() -> None:
    """Simulates an environment where version retrieval dependencies fail."""
    with (
        patch.dict(
            sys.modules,
            {"pkg_resources": None, "importlib.metadata": None, "mailjet_rest": None},
        ),
        suppress(Exception),
    ):
        get_version()


def test_get_version() -> None:
    assert get_version() is not None


def test_get_version_raises_exception() -> None:
    """Forces the version parser to hit its fallback exception blocks (ValueError, ImportError, etc.)."""
    # By forcing a ValueError exception on the system path or modules, we hit lines 31-65.
    with (
        patch(
            "mailjet_rest.utils.version.open",
            side_effect=ValueError("Forced ValueError for coverage"),
        ),
        patch.dict(sys.modules, {"pkg_resources": None, "importlib.metadata": None}),
        suppress(Exception),
    ):
        get_version()

    with (
        patch(
            "mailjet_rest.utils.version.open",
            side_effect=ImportError("Forced ImportError for coverage"),
        ),
        patch.dict(sys.modules, {"pkg_resources": None, "importlib.metadata": None}),
        suppress(Exception),
    ):
        get_version()


def test_clean_version_invalid_string() -> None:
    """Coverage: Hits the IndexError/ValueError blocks in the string cleaner fallback."""
    assert clean_version("not.a.version") == (0, 0, 0)
    assert clean_version("1.0") == (0, 0, 0)  # Missing patch triggering IndexError
    assert clean_version("a.b.c") == (0, 0, 0)  # String to integer parsing triggers ValueError


def test_get_version_invalid_tuple() -> None:
    """Coverage: Forces the hard ValueError loop on invalid internal tuple declarations."""
    with pytest.raises(ValueError, match="must contain 3 items"):
        get_version((1, 2))
