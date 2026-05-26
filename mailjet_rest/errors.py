"""Domain-specific exception hierarchy for the Mailjet SDK."""


# --- Root Base Class ---
class ApiError(Exception):
    """Base class for all API-related network errors."""


# --- New Granular Domain Exceptions ---
class MailjetNetworkError(ApiError):
    """Raised for transport-level issues (timeouts, TLS violations)."""


class MailjetApiError(ApiError):
    """Raised for 4xx/5xx API responses."""

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
    """Raised for 401/403 Authentication/Authorization failures."""


# --- Legacy Exceptions (The Bridge) ---
# We keep these as subclasses of the new hierarchy to preserve backward compatibility.


class TimeoutError(MailjetNetworkError):  # noqa: A001
    """Legacy exception: maintained for backward compatibility."""


class CriticalApiError(MailjetNetworkError):
    """Legacy exception: now a NetworkError."""


class AuthorizationError(MailjetAuthError):
    """Deprecated: The SDK natively returns the requests.Response object for 401."""


class ActionDeniedError(MailjetAuthError):
    """Deprecated: The SDK natively returns the requests.Response object for 403."""


class DoesNotExistError(MailjetApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 404."""


class ValidationError(MailjetApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 400."""


class ApiRateLimitError(MailjetApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 429."""
