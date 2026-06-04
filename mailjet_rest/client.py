"""Mailjet API v3, v3.1, and v1 Python wrapper.

This module provides the main client and helper classes for interacting
with the Mailjet API. It handles authentication, secure URL construction,
dynamic endpoint resolution, and request execution.
"""

from __future__ import annotations

import json
import logging
import sys
import warnings
from contextlib import suppress
from typing import TYPE_CHECKING, Any, ClassVar, cast

import requests  # pyright: ignore[reportMissingModuleSource]
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
    TimeoutError,  # noqa: A004
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _ALLOWED_TRACE_FIELDS
from mailjet_rest.utils.guardrails import RedactingFilter, SecureHTTPAdapter, SecurityGuard


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
    "TimeoutError",
    "ValidationError",
    "logging_handler",
    "parse_response",
]

logger = logging.getLogger(__name__)


# ==========================================
# Utilities
# ==========================================

# --- Deprecated Utilities ---


def logging_handler(to_file: bool = False, **_kwargs: Any) -> logging.Logger:  # noqa: ARG001
    """Deprecated: Custom logging handler.

    Args:
        to_file (bool): Deprecated flag. Output is no longer written to files natively.
        **_kwargs (Any): Absorbs any other legacy keyword arguments.

    Returns:
        logging.Logger: A legacy logger instance to prevent AttributeError in old integrations.
    """
    msg = (
        "logging_handler is deprecated and will be removed in future releases. "
        "Logging is now integrated cleanly and automatically via Python's standard `logging` library."
    )
    warnings.warn(msg, DeprecationWarning, stacklevel=2)

    legacy_logger = logging.getLogger("mailjet_legacy")
    legacy_logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s | %(message)s")
    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    legacy_logger.addHandler(stdout_handler)

    # Return a safe, isolated logger so downstream code like `logger.debug()` doesn't crash
    return legacy_logger


def parse_response(
    response: requests.Response,
    log: Any = None,
    debug: bool = False,
    **_kwargs: Any,
) -> Any:
    """Deprecated: Extract JSON or text from response.

    Args:
        response (requests.Response): The HTTP response.
        log (Any, optional): Deprecated logging callable.
        debug (bool): Deprecated debug flag.
        **_kwargs (Any): Absorbs any other legacy keyword arguments.

    Returns:
        Any: The parsed JSON dictionary or raw text string.
    """
    msg = (
        "parse_response is deprecated and will be removed in future releases. "
        "Please use response.json() or response.text directly on the requests.Response object."
    )
    warnings.warn(msg, DeprecationWarning, stacklevel=2)

    try:
        data = response.json()
    except ValueError:
        return response.text
    else:
        # Soft legacy support: run the logger if explicitly passed without crashing
        if debug and callable(log):
            with suppress(Exception):
                lgr = cast("logging.Logger", cast("object", log()))

                lgr.debug("REQUEST: %s", response.request.url)
                lgr.debug("RESPONSE_CODE: %s", response.status_code)
                logging.getLogger().handlers.clear()

        return data


# ==========================================
# Core Client Interface
# ==========================================


class Client:
    """The primary client for interacting with the Mailjet API.

    Handles authentication, session management, configuration, and dynamic
    endpoint resolution via magic methods (`__getattr__`).

    Examples:
        >>> client = Client(auth=(API_KEY, API_SECRET), version='v3.1')
        >>> response = client.send.create(data=payload)
    """

    _RETRY_STRATEGY: ClassVar[Retry] = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "OPTIONS"],
        respect_retry_after_header=True,  # To prevent aggressive polling
    )

    config: Config
    session: requests.Session
    _endpoint_cache: dict[str, Endpoint]

    # --- Initialization & Magic Methods ---

    def __init__(
        self,
        auth: tuple[str, str] | str | None = None,
        config: Config | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize a new Mailjet API Client instance.

        Args:
            auth (tuple[str, str] | str | None, optional): Authentication credentials.
                Use a tuple `(API_KEY, API_SECRET)` for Basic Auth (Email API).
                Use a string `TOKEN` for Bearer Auth (Content API v1).
            config (Config | None, optional): A pre-configured `Config` instance.
            **kwargs (Any): Configuration overrides if `config` is not provided
                (e.g., `version='v3.1'`, `timeout=10`).

        Raises:
            ValueError: If the provided `auth` credentials are invalid or empty.
            TypeError: If the `auth` type is neither a tuple nor a string.
        """
        self.config = config or Config(**kwargs)
        self.session = requests.Session()

        # Instance-level cache for dynamic endpoints
        self._endpoint_cache: dict[str, Endpoint] = {}

        # Expand connection pool for high-throughput batching
        adapter = SecureHTTPAdapter(max_retries=self._RETRY_STRATEGY, pool_connections=100, pool_maxsize=100)
        self.session.mount("https://", adapter)

        if auth is not None:
            if isinstance(auth, tuple):
                if len(auth) != 2:
                    msg = "Basic auth tuple must contain exactly two elements: (API_KEY, API_SECRET)."
                    raise ValueError(msg)
                self.session.auth = (str(auth[0]).strip(), str(auth[1]).strip())
            elif isinstance(auth, str):
                clean_token = auth.strip()
                if not clean_token:
                    err_msg = "Bearer token cannot be an empty string."
                    raise ValueError(err_msg)
                if "\n" in clean_token or "\r" in clean_token:
                    err_msg = "Bearer token contains invalid characters (Header Injection risk)."
                    raise ValueError(err_msg)
                self.session.headers.update({"Authorization": f"Bearer {clean_token}"})
            else:
                msg = f"Invalid auth type: expected tuple, str, or None, got {type(auth).__name__}"
                raise TypeError(msg)

        self.session.headers.update({"User-Agent": self.config.user_agent})

        if not any(isinstance(f, RedactingFilter) for f in logger.filters):
            logger.addFilter(RedactingFilter())

        # Activate the Runtime Security radar if explicitly allowed by the configuration
        if getattr(self.config, "enable_security_audit", False):
            SecurityGuard.enable_audit_logging()

    def __enter__(self) -> Self:
        """Enter the context manager.

        Returns:
            Self: The active Client instance.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the context manager and clean up resources.

        Args:
            exc_type (type[BaseException] | None): Exception type.
            exc_val (BaseException | None): Exception value.
            exc_tb (TracebackType | None): Traceback.
        """
        self.close()

    def __getattr__(self, name: str) -> Endpoint:
        """Dynamically access API endpoints as attributes.

        Args:
            name (str): Endpoint name.

        Returns:
            Endpoint: An Endpoint instance for the requested resource.
        """
        # 1. Check Cache
        if name in self._endpoint_cache:
            return self._endpoint_cache[name]

        # 2. Registry Check & Security Validation
        # If it's not in the registry, we validate it via SecurityGuard.
        # This keeps the "fail-fast" security behavior for unknown attributes.
        if name not in ROUTE_MAP:
            SecurityGuard.validate_attribute_access(self.__class__.__qualname__, name)

        # 3. Instantiate and Cache
        # Endpoint._build_url handles the URL resolution internally
        # using the ROUTE_MAP or dynamic fallback strategies.
        self._endpoint_cache[name] = Endpoint(self, name)

        return self._endpoint_cache[name]

    def __repr__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from object representation.

        Returns:
            str: A redacted string representation of the client instance.
        """
        return f"<Client API Version='{self.config.version}' URL='{self.config.api_url}'>"

    def __str__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from string representation.

        Returns:
            str: A redacted string representation.
        """
        return f"Mailjet Client ({self.config.version})"

    def __dir__(self) -> list[str]:
        """Override __dir__ to expose dynamic endpoints for IDE autocompletion.

        Returns:
            list[str]: A sorted list of all standard attributes and dynamic API endpoints.
        """
        standard_attrs = list(super().__dir__())
        return sorted(set(standard_attrs + list(ROUTE_MAP.keys())))

    # --- Public API ---

    def close(self) -> None:
        """Close the underlying requests.Session and purge memory (CWE-316)."""
        if getattr(self, "session", None):
            self.session.auth = None
            self.session.headers.clear()
            self.session.close()
            self.session = None

    @staticmethod
    def _raise_auth_error(code: int) -> None:
        msg = "Unauthorized"
        raise MailjetAuthError(msg, status_code=code)

    def _build_request_kwargs(
        self,
        method: HttpMethod,
        url: str,
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: dict[str, str] | None = None,
        timeout: TimeoutType = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Impure function: Orchestrates the API network request.

        Returns:
            requests.Response: The HTTP response object.
        """
        request_data = self._prepare_payload(data, ensure_ascii, data_encoding)
        timeout_val = timeout if timeout is not None else self.config.timeout

        SecurityGuard.check_request_security(kwargs)
        kwargs.setdefault("allow_redirects", False)
        kwargs.setdefault("verify", True)

        return {
            "method": method,
            "url": url,
            "params": filters,
            "data": request_data,
            "headers": headers,
            "timeout": timeout_val,
            **kwargs,
        }

    def _prepare_request(
        self, method: HttpMethod, url: str, **kwargs: Any
    ) -> tuple[dict[str, Any], str, dict[str, str]]:
        """Validate security, prepare kwargs, and extract telemetry.

        Returns:
            tuple[dict[str, Any], str, dict[str, str]]: Prepared request arguments,
            telemetry string, and telemetry dictionary.
        """
        req_kwargs = self._build_request_kwargs(method=method, url=url, **kwargs)
        trace_str, trace_dict = self._extract_telemetry(kwargs.get("data"), kwargs.get("headers"))

        if req_kwargs.get("timeout") is None:
            msg = "Passing 'timeout=None' allows infinite socket blocking and is deprecated (CWE-400)."
            warnings.warn(msg, DeprecationWarning, stacklevel=2)

        if not req_kwargs.get("verify", True):
            sys.audit("mailjet.api.tls_disabled", url)
            msg = "Security Violation: TLS verification disabled."
            raise ValueError(msg)

        sys.audit("mailjet.api.request", method, url)
        return req_kwargs, trace_str, trace_dict

    @staticmethod
    def _mock_dry_run_response() -> requests.Response:
        """Return a local, memory-only mock response for dry-run interception."""
        mock_resp = requests.Response()
        mock_resp.status_code = 200
        mock_resp._content = b'{"Message": "Dry run successful (No network call made)"}'  # noqa: SLF001
        return mock_resp

    def _handle_dry_run(self, method: HttpMethod, url: str, req_kwargs: dict[str, Any]) -> requests.Response | None:
        """Intercept mutations in dry-run mode.

        Returns:
            requests.Response | None: A mock response if intercepted, None otherwise.
        """
        if url.endswith("/v3.1/send") and isinstance(req_kwargs.get("data"), dict):
            req_kwargs["data"]["SandboxMode"] = True
            logger.info("DRY RUN: Injected SandboxMode into v3.1 Send payload.")
            return None

        logger.warning("DRY RUN: Intercepted %s %s. Returning mock 200 OK.", method, url)
        return self._mock_dry_run_response()

    def _execute_request(
        self, method: HttpMethod, url: str, req_kwargs: dict[str, Any], trace_str: str, trace_dict: dict[str, str]
    ) -> requests.Response:
        """Execute network call and handle errors.

        Returns:
            requests.Response: The HTTP response from the Mailjet API.
        """
        # Prevent CRLF header injection (CWE-113)
        if req_kwargs.get("headers"):
            SecurityGuard.validate_crlf_headers(req_kwargs["headers"])

        logger.debug(
            "Sending Request: %s %s%s",
            method,
            url,
            trace_str,
            extra={"http.method": method, "http.url": url, **trace_dict},
        )

        if self.config.dry_run and method in {"POST", "PUT", "DELETE"}:
            dry_run_response = self._handle_dry_run(method, url, req_kwargs)
            if dry_run_response:
                return dry_run_response

        try:
            response = self.session.request(**req_kwargs)
            if response.status_code == 401:
                self._raise_auth_error(401)
        except RequestsTimeout as e:
            logger.exception("Timeout Error: %s %s%s", method, url, trace_str)
            msg = f"Request to Mailjet API timed out: {e}"
            raise TimeoutError(msg) from e

        except RequestsConnectionError as e:
            logger.critical("Connection Error: %s | URL: %s%s", e, url, trace_str)
            msg = f"Connection to Mailjet API failed: {e}"
            raise CriticalApiError(msg) from e
        except RequestException as e:
            msg = f"An unexpected Mailjet API network error occurred: {e}"
            raise ApiError(msg) from e

        self._log_response(response, method, url, trace_str)
        return response

    def api_call(
        self,
        method: HttpMethod,
        url: str,
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: dict[str, str] | None = None,
        timeout: TimeoutType = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform the actual network request using the persistent HTTP session.

        This method acts as the core orchestrator, handling telemetry extraction,
        payload serialization, security guardrails, and centralized logging.

        Args:
            method (HttpMethod): The HTTP method.
            url (str): The fully constructed API URL.
            filters (dict[str, Any] | None, optional): Query parameters.
            data (PayloadType, optional): Request payload.
            headers (dict[str, str] | None, optional): Custom HTTP headers.
            timeout (TimeoutType, optional): Request timeout.
            ensure_ascii (bool | None, optional): Deprecated. Ensure ASCII encoding.
            data_encoding (str | None, optional): Deprecated. Data encoding string.
            **kwargs (Any): Additional arguments passed to `requests.Session.request`.

        Returns:
            requests.Response: The HTTP response from the Mailjet API.
        """
        req_kwargs, trace_str, trace_dict = self._prepare_request(
            method=method,
            url=url,
            filters=filters,
            data=data,
            headers=headers,
            timeout=timeout,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

        return self._execute_request(method, url, req_kwargs, trace_str, trace_dict)

    # --- Private / Static Helpers ---

    @staticmethod
    def _prepare_payload(data: Any, ensure_ascii: bool | None, data_encoding: str | None) -> Any:
        """Format request payload, supporting deprecated legacy serialization.

        Args:
            data (Any): Input data.
            ensure_ascii (bool | None): ASCII serialization flag.
            data_encoding (str | None): Target encoding string.

        Returns:
            Any: The formatted payload as string, bytes, or None.
        """
        if not isinstance(data, (dict, list)):
            return data

        dump_kwargs: dict[str, Any] = {}
        if ensure_ascii is not None:
            dump_kwargs["ensure_ascii"] = ensure_ascii

        request_data = json.dumps(data, **dump_kwargs)

        if data_encoding is not None and isinstance(request_data, str):
            # Return encoded bytes directly to avoid MyPy assignment conflict [str vs bytes]
            return request_data.encode(data_encoding)

        return request_data

    @staticmethod
    def _log_response(response: requests.Response, method: str, url: str, trace_str: str) -> None:
        """Centralized logging for API responses.

        Args:
            response (requests.Response): The response object.
            method (str): HTTP method.
            url (str): Target URL.
            trace_str (str): Formatted telemetry string.
        """
        try:
            is_error = response.status_code >= 400
        except TypeError:
            is_error = False

        if is_error:
            logger.error(
                "API Error %s | %s %s%s | Response: %s",
                response.status_code,
                method,
                url,
                trace_str,
                getattr(response, "text", ""),
            )
        else:
            logger.debug(
                "API Success %s | %s %s%s",
                getattr(response, "status_code", 200),
                method,
                url,
                trace_str,
            )

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
            if isinstance(data, dict):
                messages = data.get("Messages", [{}])
                target_dict = messages[0] if isinstance(messages, list) and messages else data

                for field in _ALLOWED_TRACE_FIELDS:
                    if val := target_dict.get(field) or data.get(field):
                        clean_val = SecurityGuard.sanitize_log_trace(val)
                        trace_ctx.append(f"{field}={clean_val}")
                        structured_data[f"mailjet.{field.lower()}"] = clean_val

        return f" | Trace: [{' '.join(trace_ctx)}]" if trace_ctx else "", structured_data
