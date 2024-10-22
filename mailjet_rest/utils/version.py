from __future__ import annotations


VERSION: tuple[int, int, int] = (1, 3, 3)


def get_version(version: tuple | None = None) -> str:
    """
    Calculate package version based on a 3 item tuple.
    In addition verify that the tuple contains 3 items
    """
    if version is None:
        version = VERSION
    if len(version) != 3:
        msg = "The tuple 'version' must contain 3 items"
        raise ValueError(msg)
    return "{}.{}.{}".format(*(x for x in version))
