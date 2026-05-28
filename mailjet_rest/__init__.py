"""Mailjet REST API Python Wrapper."""

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
    TimeoutError,  # noqa: A004
    ValidationError,
)
from mailjet_rest.utils.version import get_version


__version__: str = get_version()

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
