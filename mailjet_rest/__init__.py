"""Mailjet REST API Python Wrapper."""

from mailjet_rest.client import Client
from mailjet_rest.client import Config
from mailjet_rest.errors import ActionDeniedError
from mailjet_rest.errors import ApiError
from mailjet_rest.errors import ApiRateLimitError
from mailjet_rest.errors import AuthorizationError
from mailjet_rest.errors import CriticalApiError
from mailjet_rest.errors import DoesNotExistError
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.errors import MailjetAuthError
from mailjet_rest.errors import MailjetNetworkError
from mailjet_rest.errors import TimeoutError  # noqa: A004
from mailjet_rest.errors import ValidationError
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
