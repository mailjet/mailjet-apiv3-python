from __future__ import annotations

import pytest

from mailjet_rest.utils.version import get_version, VERSION


def test_version_length_equal_three() -> None:
    """Verify that the tuple contains 3 items."""
    assert len(VERSION) == 3


def test_get_version_is_none() -> None:
    """Test that package version is none."""
    version: None = None
    result: str | tuple[int, ...]
    result = get_version(version)
    assert isinstance(result, str)
    result = tuple(map(int, result.split(".")))
    assert result == VERSION
    assert isinstance(result, tuple)


def test_get_version() -> None:
    """Test that package version is string.

    Verify that if it's equal to tuple after splitting and mapped to tuple.
    """
    result: str | tuple[int, ...]
    result = get_version(VERSION)
    assert isinstance(result, str)
    result = tuple(map(int, result.split(".")))
    assert result == VERSION
    assert isinstance(result, tuple)


def test_get_version_raises_exception() -> None:
    """Test that package version raise ValueError if its length is not equal 3."""
    version: tuple[int, int] = (
        1,
        2,
    )
    with pytest.raises(ValueError):
        get_version(version)
