"""Mailjet API v3, v3.1, and v1 Python wrapper.

This module provides the main client and helper classes for interacting
with the Mailjet API. It handles authentication, secure URL construction,
dynamic endpoint resolution, and request execution.
"""

from __future__ import annotations

import difflib
import logging
import secrets
import sys
import warnings
from contextlib import suppress
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException, Timeout as RequestsTimeout
from urllib3.util.retry import Retry

from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.errors import (
    ActionDeniedError,
    ApiError,
    ApiRateLimitError,
    AuthorizationError,
    CriticalApiError,
    DoesNotExistError,
    MailjetAuthError,
    TimeoutError,  # ruff: ignore[builtin-import-shadowing]
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _ALLOWED_TRACE_FIELDS
from mailjet_rest.utils.guardrails import (
    RedactingFilter,
    SecretAuth,
    SecureHTTPAdapter,
    SecurityGuard,
)


if TYPE_CHECKING:
    from types import TracebackType

    from mailjet_rest.types import HttpMethod, PayloadType, TimeoutType

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


__all__ = [
    "ActionDeniedError",
    "ApiError",
    "ApiRateLimitError",
    "AuthorizationError",
    "Client",
    "Config",
    "CriticalApiError",
    "DoesNotExistError",
    "Endpoint",
    "MailjetAuthError",
    "TimeoutError",
    "ValidationError",
    "logging_handler",
    "parse_response",
]


# Add deep redaction filter to logger automatically
logger = logging.getLogger(__name__)
if not any(isinstance(f, RedactingFilter) for f in logger.filters):
    logger.addFilter(RedactingFilter())


class JitterRetry(Retry):
    """Custom retry policy with randomized full jitter to prevent Thundering Herd (429)."""

    def get_backoff_time(self) -> float:
        base_backoff = super().get_backoff_time()
        # Apply full jitter: random value between 0 and the exponential backoff
        return secrets.SystemRandom().uniform(0, base_backoff) if base_backoff > 0 else 0


class Client:
    """The central Mailjet API client.

    This class serves as the entry point for all interactions with the Mailjet API.
    It manages the connection pool, handles retries, and dynamically resolves
    endpoint attributes based on the static routing registry.
    """

    _RETRY_STRATEGY: ClassVar[JitterRetry] = JitterRetry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=[
            "HEAD",
            "GET",
            "OPTIONS",
            "POST",
            "PUT",
            "DELETE",
        ],  # Mutates are Idempotent-hashed safely below
    )

    def __init__(
        self,
        auth: str | tuple[str, str] | None = None,
        config: Config | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the client with jittered connection pooling.

        Args:
            auth: A tuple containing the Mailjet API key and secret, or a Bearer token string.
            config: An optional Config object for advanced behavior tuning.
            **kwargs: Configuration values (e.g., version, timeout) applied directly to a new Config object.
        """
        if auth is None:
            warnings.warn(
                "Initializing the Mailjet Client without 'auth' credentials is not recommended. "
                "If you are not injecting credentials into the session manually, your API calls will fail. "
                "Strict initialization may be enforced in SDK v2.0.0.",
                UserWarning,
                stacklevel=2,
            )

        self.config = Config(**kwargs) if config is None else config
        self.session = requests.Session()

        # Delegate auth validation and coercion to SecurityGuard
        self.auth = SecurityGuard.validate_and_coerce_auth(auth)

        if isinstance(self.auth, str):
            self.session.auth = None
            self.session.headers.update({"Authorization": f"Bearer {self.auth}"})
        elif isinstance(self.auth, SecretAuth):
            self.session.auth = self.auth
        else:
            self.session.auth = None  # type: ignore[unreachable]

        self.session.headers.update({"User-Agent": self.config.user_agent})

        adapter = SecureHTTPAdapter(pool_connections=100, pool_maxsize=100, max_retries=self._RETRY_STRATEGY)
        self.session.mount("https://", adapter)

        self._endpoint_cache: dict[str, Endpoint] = {}

        if getattr(self.config, "enable_security_audit", False):
            SecurityGuard.enable_audit_logging()

    def __enter__(self) -> Self:
        """Enter the context manager and return the client instance.

        Returns:
            Self: The client instance.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context manager and safely close the HTTP session.

        Args:
            exc_type (type[BaseException] | None): Exception type.
            exc_val (BaseException | None): Exception value.
            exc_tb (TracebackType | None): Traceback.
        """
        self.close()

    def __repr__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from object representation.

        Returns:
            str: The sanitized and safe string representation of the client instance.
        """
        return f"<Client API Version='{self.config.version}' URL='{self.config.api_url}'>"

    def __str__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from string representation.

        Returns:
            str: The sanitized client string.
        """
        return f"Mailjet Client ({self.config.version})"

    def close(self) -> None:
        """Secure resource teardown closing internal sockets."""
        if hasattr(self, "session") and self.session:
            self.session.auth = None
            self.session.headers.clear()
            self.session.close()

    def __getattr__(self, name: str) -> Endpoint:
        """O(1) Route mapping.

        Dynamically returns an Endpoint tied to the requested resource.

        Returns:
            Endpoint: A dynamically created endpoint instance mapping to the route.
        """
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

        if name in self._endpoint_cache:
            return self._endpoint_cache[name]

        # Fail fast for typos: Only check simple un-composited names.
        # A cutoff of 0.8 catches obvious mistakes like 'snd'->'send' or 'session'->'session',
        # but allows legitimate dynamic endpoints to pass through to the fallback.
        if "_" not in name and name not in ROUTE_MAP and difflib.get_close_matches(name, dir(self), n=1, cutoff=0.8):
            msg = f"'{self.__class__.__name__}' has no endpoint or attribute '{name}'."
            raise AttributeError(msg)

        # If it doesn't exist, we fall back to assuming it's a dynamic path
        # which will be safely encoded by sanitize_segment during _build_url
        endpoint = Endpoint(client=self, name=name)
        self._endpoint_cache[name] = endpoint
        return endpoint

    def __dir__(self) -> list[str]:
        """Expose dynamic routing attributes for IDE autocompletion.

        Returns:
            list[str]: The list of standard attributes plus available dynamic endpoints.
        """
        return sorted(set(list(super().__dir__()) + list(ROUTE_MAP.keys())))

    def _execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, Any],
        data: Any,
        params: dict[str, Any] | None,
        timeout: Any,
        **kwargs: Any,
    ) -> requests.Response:
        """Isolated HTTP execution to reduce complexity and handle core network logic.

        Returns:
            requests.Response: The raw HTTP response directly from the network.
        """
        kwargs.pop("verify", None)

        # Strip out headers with None values to let requests auto-generate multipart boundaries
        clean_headers = {k: v for k, v in headers.items() if v is not None}

        content_type = clean_headers.get("Content-Type", "")
        is_json = isinstance(data, (dict, list)) and "application/json" in content_type

        return self.session.request(
            method=method,
            url=url,
            headers=clean_headers,
            json=data if is_json else None,
            data=data if not is_json else None,
            params=params,
            timeout=timeout,
            verify=True,  # Always True, enforced natively against MITM attacks
            **kwargs,
        )

    @staticmethod
    def _handle_api_error(e: RequestException) -> NoReturn:
        """Map requests exceptions to Mailjet specific API errors."""
        if e.response is not None:
            status = e.response.status_code
            body = e.response.text

            # DX Improvement: Extract actionable error message from API response
            error_detail = ""
            with suppress(Exception):
                resp_json = e.response.json()
                if "ErrorMessage" in resp_json:
                    error_detail = f": {resp_json['ErrorMessage']}"
                elif resp_json.get("Messages"):
                    errors = resp_json["Messages"][0].get("Errors", [])
                    if errors:
                        error_detail = f": {errors[0].get('ErrorMessage', '')}"

            if not error_detail and body:
                error_detail = f": {body}"

            if status in {401, 403}:
                msg = f"Authentication or Authorization failed{error_detail}"
                raise MailjetAuthError(msg, status, body) from e
            if status == 429:
                msg = f"Rate limit exceeded{error_detail}"
                raise ApiRateLimitError(msg, status, body) from e
            if status == 404:
                msg = f"Resource not found{error_detail}"
                raise DoesNotExistError(msg, status, body) from e
            if status == 400:
                msg = f"Payload validation failed{error_detail}"
                raise ValidationError(msg, status, body) from e

        msg = f"An unexpected Mailjet API network error occurred: {e}"
        raise ApiError(msg) from e

    def api_call(  # ruff: ignore[complex-structure]
        self,
        method: HttpMethod,
        url: str,
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: dict[str, str] | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the authenticated API call with idempotency guards.

        Args:
            method (HttpMethod): The HTTP method.
            url (str): The fully constructed API URL.
            filters (dict[str, Any] | None, optional): Query parameters.
            data (PayloadType, optional): Request payload.
            headers (dict[str, str] | None, optional): Custom HTTP headers.
            timeout (TimeoutType, optional): Request timeout.
            **kwargs (Any): Additional arguments passed to 'requests.Session.request'.

        Returns:
            requests.Response: The authenticated HTTP response from Mailjet.
        """
        # Ensure headers is a dictionary to prevent crashes if a legacy call explicitly passes None,
        # or relies on the default fallback, before we attempt to mutate it for Idempotency keys.
        if headers is None:
            headers = {}

        # CWE-113: Prevent Request Smuggling / CRLF Injection in headers
        headers = SecurityGuard.sanitize_headers(headers)

        if not kwargs.get("verify", True):
            sys.audit("mailjet.security.tls_disabled", url)
            msg = "Security Violation: Mailjet API TLS verification cannot be disabled."
            raise ValueError(msg)

        # Safely determine and validate active timeout bounds (CWE-400)
        active_timeout = timeout if timeout is not None else self.config.timeout
        req_timeout = SecurityGuard.validate_timeout(active_timeout)

        # Proxy Security Guardrail
        SecurityGuard.check_request_security(kwargs)

        # CWE-915: Prevent Mass Assignment of internal HTTP client states
        safe_kwargs = SecurityGuard.filter_safe_kwargs(kwargs)

        # Idempotency Lock for mutations
        if method in {"POST", "PUT", "DELETE"}:
            if self.config.dry_run:
                logger.info("DRY RUN: Intercepted %s request to %s", method, url)
                mock = requests.Response()
                mock.status_code = 200
                return mock

            # Allow idempotency hashing for valid batch lists
            if isinstance(data, (dict, list)) and "Idempotency-Key" not in headers:
                headers["Idempotency-Key"] = SecurityGuard.generate_payload_fingerprint(data)

        # Strip None filters
        clean_filters = {k: v for k, v in filters.items() if v is not None} if filters else None

        trace_suffix, _ = self._extract_telemetry(data, headers)

        try:
            response = self._execute_request(
                method=method,
                url=url,
                headers=headers,
                data=data,
                params=clean_filters,
                timeout=req_timeout,
                **safe_kwargs,
            )
            response.raise_for_status()

        except RequestsTimeout as e:
            logger.exception("Timeout Error: %s %s", method, url)
            msg = f"Request to Mailjet API timed out: {e}"
            raise TimeoutError(msg) from e

        except RequestsConnectionError as e:
            msg = f"Connection to Mailjet API failed: {e}"
            raise CriticalApiError(msg) from e

        except RequestException as e:
            self._handle_api_error(e)

        else:
            if response.status_code in {200, 201, 204}:
                self._log_request(method, url, response, trace_suffix)
            return response

    @staticmethod
    def _log_request(method: str, url: str, response: requests.Response, trace_str: str) -> None:
        """Internal static logging mechanism for formatted API lifecycle traces."""
        if response.status_code >= 400:
            logger.error(
                "API Error %s | %s %s%s | Response: %s",
                getattr(response, "status_code", "Unknown"),
                method,
                url,
                trace_str,
                getattr(response, "text", ""),
            )
        else:
            logger.debug("API Success %s | %s %s%s", getattr(response, "status_code", 200), method, url, trace_str)

    @staticmethod
    def _extract_telemetry(data: Any, _headers: dict[str, str] | None) -> tuple[str, dict[str, str]]:
        """Extract tracing identifiers for safe logging and structured telemetry.

        Args:
            data (Any): The request payload.

        Returns:
            tuple[str, dict[str, str]]: A tuple containing the formatted telemetry trace suffix
                and a dictionary of structured data.
        """
        trace_ctx = []
        structured_data = {}
        with suppress(Exception):
            if isinstance(data, (dict, list)):
                # Correctly unpack top-level list payloads instead of falling back to [{}]
                messages = data.get("Messages", [{}]) if isinstance(data, dict) else data
                target_dict = messages[0] if isinstance(messages, list) and messages else data

                if isinstance(target_dict, dict):
                    for field in _ALLOWED_TRACE_FIELDS:
                        if val := target_dict.get(field) or (isinstance(data, dict) and data.get(field)):
                            clean_val = SecurityGuard.sanitize_log_trace(val)
                            trace_ctx.append(f"{field}={clean_val}")
                            structured_data[f"mailjet.{field.lower()}"] = clean_val

        return f" | Trace: [{' '.join(trace_ctx)}]" if trace_ctx else "", structured_data


# --- Deprecated Wrappers ---
def parse_response(response: requests.Response) -> Any:
    """Parse the JSON response or return text if invalid.

    Returns:
        Any: The JSON dictionary structure or the raw text of the response body.
    """
    warnings.warn("parse_response is deprecated.", DeprecationWarning, stacklevel=2)
    try:
        return response.json()
    except ValueError:
        return response.text


def logging_handler(client: Any) -> None:  # ruff: ignore[unused-function-argument]
    """Legacy logging handler (deprecated)."""
    warnings.warn("logging_handler is deprecated.", DeprecationWarning, stacklevel=2)
