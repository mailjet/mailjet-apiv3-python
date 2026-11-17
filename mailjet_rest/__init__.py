"""Mailjet REST API Python Wrapper."""

from __future__ import annotations

import importlib
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from mailjet_rest.client import AsyncClient, Client, Config
    from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
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
    "AsyncClient": ("mailjet_rest.client", "AsyncClient"),
    "AsyncEndpoint": ("mailjet_rest.endpoint", "AsyncEndpoint"),
    "AuthorizationError": ("mailjet_rest.errors", "AuthorizationError"),
    "Client": ("mailjet_rest.client", "Client"),
    "Config": ("mailjet_rest.client", "Config"),
    "CriticalApiError": ("mailjet_rest.errors", "CriticalApiError"),
    "DoesNotExistError": ("mailjet_rest.errors", "DoesNotExistError"),
    "Endpoint": ("mailjet_rest.endpoint", "Endpoint"),
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
    "AsyncClient",
    "AsyncEndpoint",
    "AuthorizationError",
    "Client",
    "Config",
    "CriticalApiError",
    "DoesNotExistError",
    "Endpoint",
    "MailjetApiError",
    "MailjetAuthError",
    "MailjetNetworkError",
    "TimeoutError",
    "ValidationError",
    "get_version",
]


def _import_known_submodule(module_name: str) -> Any:
    """Import an allowlisted internal submodule using string literals only.

    Returns:
        Any: The imported internal submodule object.
    """
    if module_name == "mailjet_rest.client":
        return importlib.import_module("mailjet_rest.client")
    if module_name == "mailjet_rest.endpoint":
        return importlib.import_module("mailjet_rest.endpoint")
    if module_name == "mailjet_rest.errors":
        return importlib.import_module("mailjet_rest.errors")
    if module_name == "mailjet_rest.utils.version":
        return importlib.import_module("mailjet_rest.utils.version")
    msg = f"Disallowed lazy submodule: {module_name!r}"
    raise ImportError(msg)


def __getattr__(name: str) -> Any:
    """Resolve top-level SDK exports lazily via PEP 562.

    Returns:
        Any: The resolved class, function, or version string.
    """
    if name == "__version__":
        version_mod = _import_known_submodule("mailjet_rest.utils.version")
        value = version_mod.get_version()
        globals()[name] = value
        return value

    target = _LAZY_EXPORTS.get(name)
    if target is None:
        msg = f"module 'mailjet_rest' has no attribute {name!r}"
        raise AttributeError(msg)

    module_name, attr_name = target
    value = getattr(_import_known_submodule(module_name), attr_name)
    globals()[name] = value
    return value


def __dir__() -> list[str]:
    """Return top-level exports including lazy attributes for introspection tools.

    Returns:
        list[str]: Sorted list of exposed attributes.
    """
    return sorted({*globals(), *__all__, "__version__"})
