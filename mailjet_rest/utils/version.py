"""Versioning utilities for the Mailjet REST API client.

This module defines the current version of the Mailjet client and provides
a helper function, `get_version`, to retrieve the version as a formatted string.

Attributes:
    VERSION (tuple[int, int, int]): A tuple representing the major, minor, and patch
    version of the package.

Functions:
    get_version: Returns the version as a string in the format "major.minor.patch".
"""

from __future__ import annotations

import re
from typing import Final

from mailjet_rest._version import __version__ as package_version


_LEADING_DIGITS_RE: Final[re.Pattern[str]] = re.compile(r"^(\d+)")


def parse_semver_triplet(raw_version: str) -> tuple[int, int, int]:
    """Extract numeric (major, minor, patch) without merging pre-release digits.

    Returns:
        tuple[int, int, int]: The parsed numeric semantic version triplet.

    Raises:
        ValueError: If the version string does not start with an X.Y.Z triplet.
    """
    parts = raw_version.strip().split(".")
    if len(parts) < 3 or not parts[0].isdigit() or not parts[1].isdigit():
        msg = f"Expected X.Y.Z version string, got {raw_version!r}"
        raise ValueError(msg)

    match = _LEADING_DIGITS_RE.match(parts[2])
    if match is None:
        msg = f"Invalid patch component in {raw_version!r}"
        raise ValueError(msg)

    return int(parts[0]), int(parts[1]), int(match.group(1))


def clean_version(version_str: str) -> tuple[int, ...]:
    """Clean package version string into 3 item tuple.

    Parameters:
    version_str (str): A string of the package version.

    Returns:
    tuple: A tuple representing the version of the package.
    """
    try:
        return parse_semver_triplet(version_str)
    except (ValueError, TypeError, AttributeError):
        return 0, 0, 0


# VERSION is a tuple of integers (1, 3, 2).
VERSION: tuple[int, ...] = clean_version(package_version)


def get_version(version: tuple[int, ...] | None = None) -> str:
    """Calculate package version based on a 3 item tuple.

    In addition, verify that the tuple contains 3 items.

    Parameters:
    version (tuple[int, ...], optional): A tuple representing the version of the package.
        If not provided, the function will use the VERSION constant.
        Default is None.

    Returns:
    str: The version as a string in the format "major.minor.patch".

    Raises:
    ValueError: If the provided tuple does not contain exactly 3 items.
    """
    if version is None:
        version = VERSION
    if len(version) != 3:
        msg = "The tuple 'version' must contain 3 items"
        raise ValueError(msg)
    return f"{version[0]}.{version[1]}.{version[2]}"
