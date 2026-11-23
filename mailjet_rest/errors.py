"""Domain-specific exception hierarchy and HTTP error mapping for the Mailjet SDK."""

from __future__ import annotations

import builtins
import re
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Final, NoReturn


if TYPE_CHECKING:
    import logging


__all__ = [
    "MAX_ERROR_BODY_CHARS",
    "MAX_ERROR_DETAIL_CHARS",
    "MAX_ERROR_LOG_CHARS",
    "ActionDeniedError",
    "ApiError",
    "ApiRateLimitError",
    "AuthorizationError",
    "CriticalApiError",
    "DoesNotExistError",
    "MailjetApiError",
    "MailjetAuthError",
    "MailjetNetworkError",
    "TimeoutError",
    "ValidationError",
    "extract_error_detail",
    "handle_api_error",
    "raise_connection_error",
    "raise_mapped_http_error",
    "raise_timeout_error",
    "sanitize_error_text",
]


MAX_ERROR_LOG_CHARS: Final[int] = 2048
MAX_ERROR_DETAIL_CHARS: Final[int] = 1024
MAX_ERROR_BODY_CHARS: Final[int] = 16384
_LOG_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x1f\x7f]")


# --- Root Base Class ---
class ApiError(Exception):
    """Base class for all Mailjet transport and HTTP API errors."""


# --- New Granular Domain Exceptions ---
class MailjetNetworkError(ApiError):
    """Raised for transport-level issues (timeouts, connection failures, TLS violations)."""


class MailjetApiError(ApiError):
    """Raised for unhandled HTTP 4xx/5xx API error responses."""

    def __init__(self, message: str, status_code: int = 0, response_body: str = "") -> None:
        """Initialize the API error.

        Args:
            message: The error message.
            status_code: HTTP status code.
            response_body: The raw response content.
        """
        super().__init__(message)
        self.status_code = status_code
        self.response_body = response_body


class MailjetAuthError(MailjetApiError):
    """Raised for 401/403 Authentication or Authorization failures."""


# --- Legacy Exceptions (The Bridge) ---
# Kept as subclasses of the modern hierarchy to preserve backward compatibility.


class TimeoutError(MailjetNetworkError, builtins.TimeoutError):  # ruff: ignore[builtin-variable-shadowing]
    """Raised on request timeouts; satisfies both ``MailjetNetworkError`` and ``builtins.TimeoutError``."""


class CriticalApiError(MailjetNetworkError):
    """Legacy exception raised on connection failures; prefer MailjetNetworkError."""


class AuthorizationError(MailjetAuthError):
    """Deprecated alias for HTTP 401 failures; client raises MailjetAuthError."""


class ActionDeniedError(MailjetAuthError):
    """Deprecated alias for HTTP 403 failures; client raises MailjetAuthError."""


class DoesNotExistError(MailjetApiError):
    """Raised on HTTP 404 responses (legacy alias extending MailjetApiError)."""


class ValidationError(MailjetApiError):
    """Raised on HTTP 400 and payload validation errors (legacy alias extending MailjetApiError)."""


class ApiRateLimitError(MailjetApiError):
    """Raised on HTTP 429 rate-limit responses (legacy alias extending MailjetApiError)."""


_HTTP_ERROR_MAP: Final[dict[int, tuple[type[MailjetApiError], str]]] = {
    400: (ValidationError, "Payload validation failed"),
    401: (MailjetAuthError, "Authentication or Authorization failed"),
    403: (MailjetAuthError, "Authentication or Authorization failed"),
    404: (DoesNotExistError, "Resource not found"),
    429: (ApiRateLimitError, "Rate limit exceeded"),
}


def sanitize_error_text(raw: Any, *, max_chars: int) -> str:
    """Truncate raw error text and neutralize control characters (CWE-117).

    Returns:
        str: Bounded single-line safe error text.
    """
    text = str(raw or "")
    if len(text) > max_chars:
        text = f"{text[:max_chars]}...[truncated]"
    return _LOG_CONTROL_CHAR_RE.sub(" ", text)


def _extract_json_error_message(response: Any) -> str:
    resp_json = response.json()
    if not isinstance(resp_json, dict):
        return ""
    if "ErrorMessage" in resp_json:
        return str(resp_json["ErrorMessage"])
    messages = resp_json.get("Messages")
    if isinstance(messages, list) and messages and isinstance(messages[0], dict):
        errors = messages[0].get("Errors")
        if isinstance(errors, list) and errors and isinstance(errors[0], dict):
            return str(errors[0].get("ErrorMessage", ""))
    return ""


def extract_error_detail(
    response: Any,
    body: str,
    *,
    max_chars: int = MAX_ERROR_DETAIL_CHARS,
) -> str:
    """Extract a bounded, control-char-neutralized error summary from a Mailjet response.

    Returns:
        str: Formatted error suffix (leading ': ...') or empty string.
    """
    raw_detail = ""
    with suppress(Exception):
        raw_detail = _extract_json_error_message(response)
    if not raw_detail:
        raw_detail = body
    if not raw_detail:
        return ""
    clean_detail = sanitize_error_text(raw_detail, max_chars=max_chars)
    return f": {clean_detail}" if clean_detail else ""


def raise_mapped_http_error(
    response: Any,
    exc: Exception,
    *,
    max_chars: int = MAX_ERROR_DETAIL_CHARS,
) -> NoReturn:
    """Map an HTTP response status code to the Mailjet exception hierarchy."""
    status = int(response.status_code)
    raw_body = str(getattr(response, "text", "") or "")
    error_detail = extract_error_detail(response, raw_body, max_chars=max_chars)
    body = f"{raw_body[:MAX_ERROR_BODY_CHARS]}...[truncated]" if len(raw_body) > MAX_ERROR_BODY_CHARS else raw_body

    if entry := _HTTP_ERROR_MAP.get(status):
        exc_cls, prefix = entry
        msg = f"{prefix}{error_detail}"
        raise exc_cls(msg, status, body) from exc
    if status >= 400:
        msg = f"Mailjet API HTTP {status}{error_detail}"
        raise MailjetApiError(msg, status, body) from exc

    msg = f"An unexpected Mailjet API network error occurred: {exc}"
    raise ApiError(msg) from exc


def handle_api_error(
    exc: Exception,
    *,
    max_chars: int = MAX_ERROR_DETAIL_CHARS,
) -> NoReturn:
    """Map transport or HTTP status exceptions to Mailjet-specific API errors."""
    response = getattr(exc, "response", None)
    if response is not None:
        raise_mapped_http_error(response, exc, max_chars=max_chars)

    msg = f"An unexpected Mailjet API network error occurred: {exc}"
    raise ApiError(msg) from exc


def raise_timeout_error(log: logging.Logger, method: str, url: str, exc: Exception) -> NoReturn:
    """Log a sanitized timeout notice and raise TimeoutError preserving cause."""
    log.error("Timeout Error: %s %s", method, url, exc_info=exc)
    msg = f"Request to Mailjet API timed out: {exc}"
    raise TimeoutError(msg) from exc


def raise_connection_error(exc: Exception) -> NoReturn:
    """Raise CriticalApiError for transport connection failures preserving cause."""
    msg = f"Connection to Mailjet API failed: {exc}"
    raise CriticalApiError(msg) from exc
