"""Domain-specific exception hierarchy for the Mailjet SDK."""


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


class TimeoutError(MailjetNetworkError):  # ruff: ignore[builtin-variable-shadowing]
    """Legacy exception raised on request timeouts; prefer MailjetNetworkError."""


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
