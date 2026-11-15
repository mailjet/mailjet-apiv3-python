"""Mailjet REST API Python Wrapper."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from mailjet_rest.client import Client, Config
    from mailjet_rest.errors import (
        ActionDeniedError,
        ApiError,
        ApiRateLimitError,
        AuthorizationError,
        CriticalApiError,
        DoesNotExistError,
        MailjetApiError,
        MailjetAuthError,
        MailjetNetworkError,
        TimeoutError,  # ruff: ignore[builtin-import-shadowing]
        ValidationError,
    )
    from mailjet_rest.utils.version import get_version

    __version__: str


_LAZY_EXPORTS: dict[str, tuple[str, str]] = {
    "ActionDeniedError": ("mailjet_rest.errors", "ActionDeniedError"),
    "ApiError": ("mailjet_rest.errors", "ApiError"),
    "ApiRateLimitError": ("mailjet_rest.errors", "ApiRateLimitError"),
    "AuthorizationError": ("mailjet_rest.errors", "AuthorizationError"),
    "Client": ("mailjet_rest.client", "Client"),
    "Config": ("mailjet_rest.client", "Config"),
    "CriticalApiError": ("mailjet_rest.errors", "CriticalApiError"),
    "DoesNotExistError": ("mailjet_rest.errors", "DoesNotExistError"),
    "MailjetApiError": ("mailjet_rest.errors", "MailjetApiError"),
    "MailjetAuthError": ("mailjet_rest.errors", "MailjetAuthError"),
    "MailjetNetworkError": ("mailjet_rest.errors", "MailjetNetworkError"),
    "TimeoutError": ("mailjet_rest.errors", "TimeoutError"),
    "ValidationError": ("mailjet_rest.errors", "ValidationError"),
    "get_version": ("mailjet_rest.utils.version", "get_version"),
}

__all__ = [
    "ActionDeniedError",
    "ApiError",
    "ApiRateLimitError",
    "AuthorizationError",
    "Client",
    "Config",
    "CriticalApiError",
    "DoesNotExistError",
    "MailjetApiError",
    "MailjetAuthError",
    "MailjetNetworkError",
    "TimeoutError",
    "ValidationError",
    "get_version",
]


def __getattr__(name: str) -> Any:
    """Resolve top-level SDK exports lazily via PEP 562.

    Returns:
        Any: The resolved class, function, or version string.
    """
    if name == "__version__":
        version_mod = importlib.import_module("mailjet_rest.utils.version")
        value = version_mod.get_version()
        globals()[name] = value
        return value

    target = _LAZY_EXPORTS.get(name)
    if target is None:
        msg = f"module 'mailjet_rest' has no attribute {name!r}"
        raise AttributeError(msg)

    module_name, attr_name = target
    value = getattr(importlib.import_module(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return top-level exports including lazy attributes for introspection tools.

    Returns:
        list[str]: Sorted list of exposed attributes.
    """
    return sorted({*globals(), *__all__, "__version__"})
