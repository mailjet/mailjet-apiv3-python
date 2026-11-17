"""Mailjet API v3, v3.1, and v1 Python wrapper.

This module provides the synchronous (Client) and asynchronous (AsyncClient)
classes for interacting with the Mailjet API using requests (sync) and httpx2 (async).
It handles authentication, secure URL construction, dynamic endpoint resolution,
and request execution.
"""

from __future__ import annotations

import asyncio
import copy
import importlib
import logging
import math
import secrets
import sys
import threading
import uuid
import warnings
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Any, ClassVar, NoReturn, TypeVar

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException, Timeout as RequestsTimeout
from urllib3.util.retry import Retry

from mailjet_rest.config import Config
from mailjet_rest.endpoint import AsyncEndpoint, BaseEndpoint, Endpoint
from mailjet_rest.errors import (
    ActionDeniedError,
    ApiError,
    ApiRateLimitError,
    AuthorizationError,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    TimeoutError,  # ruff: ignore[builtin-import-shadowing]
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _ALLOWED_TRACE_FIELDS, _DEFAULT_TIMEOUT
from mailjet_rest.utils.guardrails import (
    RedactingFilter,
    SecretAuth,
    SecureHTTPAdapter,
    SecurityGuard,
)
from mailjet_rest.utils.transport_security import (
    _KEEPALIVE_SOCKET_OPTIONS,
    build_ssl_context_with_cert,
    get_secure_ssl_context,
)


if TYPE_CHECKING:
    from types import TracebackType

    import httpx2

    from mailjet_rest.types import HttpMethod, PayloadType, TimeoutType

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


__all__ = [
    "ActionDeniedError",
    "ApiError",
    "ApiRateLimitError",
    "AsyncClient",
    "AsyncEndpoint",
    "AuthorizationError",
    "BaseClient",
    "Client",
    "Config",
    "CriticalApiError",
    "DoesNotExistError",
    "Endpoint",
    "MailjetApiError",
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

_EndpointT = TypeVar("_EndpointT", bound=BaseEndpoint)
_httpx2_cache: list[Any] = []


def _get_httpx2() -> Any:
    """Lazily import httpx2 on first AsyncClient use without slowing sync boot.

    Returns:
        Any: The imported httpx2 module, or None if unavailable.
    """
    if not _httpx2_cache:
        try:
            mod = importlib.import_module("httpx2")
        except ImportError:
            return None
        _httpx2_cache.append(mod)
    return _httpx2_cache[0]


def _require_httpx2() -> Any:
    """Return the httpx2 module or raise an actionable ImportError when missing.

    Returns:
        Any: The imported httpx2 module.
    """
    mod = globals()["_httpx2"] if "_httpx2" in globals() else _get_httpx2()
    if mod is None:
        msg = "AsyncClient requires 'httpx2>=2.0.0'. Install with: pip install 'mailjet-rest[async]'"
        raise ImportError(msg)
    return mod


def __getattr__(name: str) -> Any:
    """Resolve optional _httpx2 attribute lazily on module access.

    Returns:
        Any: The lazily loaded httpx2 module when requesting '_httpx2'.
    """
    if name == "_httpx2":
        return _get_httpx2()
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


class JitterRetry(Retry):
    """Custom retry policy with randomized full jitter to prevent Thundering Herd (429)."""

    def get_backoff_time(self) -> float:
        """Compute exponential backoff with randomized full jitter.

        Returns:
            float: Delay duration in seconds before retrying.
        """
        base_backoff = super().get_backoff_time()
        # Apply full jitter: random value between 0 and the exponential backoff
        return secrets.SystemRandom().uniform(0, base_backoff) if base_backoff > 0 else 0


class BaseClient:
    """Shared configuration, TLS policy, telemetry, and error handling for sync and async clients."""

    __slots__ = ("_closed", "_endpoint_cache", "_lock", "_session", "auth", "config")

    _MUTATING_METHODS: ClassVar[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    _TRANSIENT_STATUS_CODES: ClassVar[frozenset[int]] = frozenset({429, 500, 502, 503, 504})
    _MAX_RETRY_DELAY: ClassVar[float] = 60.0
    _RETRY_ALLOWED_METHODS: ClassVar[tuple[str, ...]] = (
        "HEAD",
        "GET",
        "OPTIONS",
        "POST",
        "PUT",
        "PATCH",
        "DELETE",
    )

    _RETRY_STRATEGY: ClassVar[JitterRetry] = JitterRetry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=list(_RETRY_ALLOWED_METHODS),  # Mutates are Idempotent-hashed safely below
    )

    def __init__(
        self,
        auth: str | tuple[str, str] | None = None,
        config: Config | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize base client configuration, TLS policy, and auth credentials.

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
                stacklevel=3,
            )

        self._init_runtime_state()
        self.config = Config(**kwargs) if config is None else config
        SecurityGuard.resolve_tls_verify(self.config.verify)

        # Delegate auth validation and coercion to SecurityGuard
        self.auth = SecurityGuard.validate_and_coerce_auth(auth)

        if getattr(self.config, "enable_security_audit", False):
            SecurityGuard.enable_audit_logging()

    def _validate_endpoint_name(self, name: str) -> None:
        """Validate dynamic endpoint attribute lookups and reject typos."""
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

        # Fail fast for typos: Only check simple un-composited names.
        # A cutoff of 0.8 catches obvious mistakes like 'snd'->'send' or 'session'->'session',
        # but allows legitimate dynamic endpoints to pass through to the fallback.
        if "_" not in name and name not in ROUTE_MAP:
            import difflib  # ruff: ignore[import-outside-top-level]

            if difflib.get_close_matches(name, dir(self), n=1, cutoff=0.8):
                msg = f"'{self.__class__.__name__}' has no endpoint or attribute '{name}'."
                raise AttributeError(msg)

    def _resolve_endpoint(self, name: str, endpoint_cls: type[_EndpointT]) -> _EndpointT:
        """Resolve and cache an endpoint instance in a thread-safe manner.

        Returns:
            _EndpointT: Cached or newly created endpoint instance.
        """
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

        with self._lock:
            if name in self._endpoint_cache:
                cached: _EndpointT = self._endpoint_cache[name]
                return cached

        self._validate_endpoint_name(name)

        # If it doesn't exist in ROUTE_MAP, fall back to dynamic routing which
        # sanitizes every path segment inside BaseEndpoint._build_url.
        with self._lock:
            resolved: _EndpointT = self._endpoint_cache.setdefault(
                name,
                endpoint_cls(client=self, name=name),
            )
            return resolved

    def __repr__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from object representation.

        Returns:
            str: The sanitized and safe string representation of the client instance.
        """
        return f"<{self.__class__.__name__} API Version='{self.config.version}' URL='{self.config.api_url}'>"

    def __str__(self) -> str:
        """OWASP Secrets Management: Redact sensitive information from string representation.

        Returns:
            str: The sanitized client string.
        """
        return f"Mailjet {self.__class__.__name__} ({self.config.version})"

    def _init_runtime_state(self) -> None:
        self._lock = threading.RLock()
        self._closed = False
        self._session: Any = None
        self._endpoint_cache: Any = {}

    @classmethod
    def _create_uninitialized(cls) -> Self:
        instance = cls.__new__(cls)
        cls._init_runtime_state(instance)
        return instance

    def _clone(self, memo: dict[int, Any] | None = None) -> Self:
        cloned = self._create_uninitialized()
        if memo is not None:
            memo[id(self)] = cloned
            cloned.config = copy.deepcopy(self.config, memo)
            cloned.auth = copy.deepcopy(self.auth, memo)
        else:
            cloned.config = copy.copy(self.config)
            cloned.auth = self.auth
        return cloned

    def __copy__(self) -> Self:
        """Create a shallow copy of the client with an isolated fresh session state.

        Returns:
            Self: New client instance sharing configuration without open sockets.
        """
        return self._clone()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        """Create a deep copy of the client with an isolated fresh session state.

        Args:
            memo: Memoization mapping for recursive deep copy tracking.

        Returns:
            Self: Deeply copied client instance with fresh runtime session state.
        """
        return self._clone(memo)

    @classmethod
    def _compute_retry_delay(cls, attempt: int, retry_after_header: str | None = None) -> float:
        """Compute full-jitter backoff or capped Retry-After delay in seconds.

        Args:
            attempt: Zero-based retry attempt index.
            retry_after_header: Optional raw Retry-After response header value.

        Returns:
            float: Delay duration in seconds bounded by _MAX_RETRY_DELAY.
        """
        if isinstance(retry_after_header, str):
            stripped = retry_after_header.strip()
            if stripped:
                with suppress(ValueError):
                    parsed = float(stripped)
                    if math.isfinite(parsed) and parsed >= 0:
                        return min(parsed, cls._MAX_RETRY_DELAY)

        bounded_exponent = max(0, min(attempt, 20))
        base_backoff = min(float(2**bounded_exponent), cls._MAX_RETRY_DELAY)
        return secrets.SystemRandom().uniform(0.0, base_backoff)

    @staticmethod
    def _reset_stream_pointers(data: Any, files: Any) -> None:
        """Rewind seekable payload and multipart file streams before retrying a request."""
        stack: list[tuple[Any, int]] = [(data, 0), (files, 0)]
        while stack:
            item, depth = stack.pop()
            if item is None or depth > 4:
                continue
            seek_fn = getattr(item, "seek", None)
            if callable(seek_fn) and not getattr(item, "closed", False):
                seekable_fn = getattr(item, "seekable", None)
                if not callable(seekable_fn) or seekable_fn():
                    with suppress(OSError, ValueError):
                        seek_fn(0)
                continue
            if isinstance(item, (Mapping, list, tuple)):
                children = item.values() if isinstance(item, Mapping) else item
                stack.extend((elem, depth + 1) for elem in children)

    @staticmethod
    def _prepare_clean_headers(headers: Mapping[str, Any], files: Any = None) -> dict[str, Any]:
        """Strip None headers and remove default application/json Content-Type on multipart uploads.

        Args:
            headers: Raw request headers mapping.
            files: Optional multipart files argument.

        Returns:
            dict[str, Any]: Sanitized headers ready for transport execution.
        """
        clean_headers = {k: v for k, v in headers.items() if v is not None}
        if files:
            for key in list(clean_headers):
                val = clean_headers[key]
                if key.lower() == "content-type" and isinstance(val, str) and val.strip().lower() == "application/json":
                    del clean_headers[key]
        return clean_headers

    def _ping_url(self) -> str:
        """Construct the lightweight credential/connectivity probe URL.

        Returns:
            str: Fully qualified probe endpoint URL.
        """
        return f"{self.config.api_url.rstrip('/')}/v3/REST/apikey"

    def __dir__(self) -> list[str]:
        """Expose dynamic routing attributes for IDE autocompletion.

        Returns:
            list[str]: The list of standard attributes plus available dynamic endpoints.
        """
        return sorted(set(list(super().__dir__()) + list(ROUTE_MAP.keys())))

    def _warn_if_unclosed(self) -> None:
        """Emit ResourceWarning if an opened session was not explicitly closed."""
        try:
            closed = self._closed
            session = self._session
            config = self.config
        except AttributeError:
            return

        if closed or session is None:
            return

        if config.warn_unclosed:
            if isinstance(self, AsyncClient):
                msg = "Unclosed Mailjet AsyncClient session; call await client.aclose() or use 'async with'."
            else:
                msg = "Unclosed Mailjet Client session; call client.close() or use a context manager."
            warnings.warn(msg, ResourceWarning, stacklevel=3)

    def __del__(self) -> None:
        """Delegate optional unclosed-session check on garbage collection."""
        self._warn_if_unclosed()

    @staticmethod
    def _extract_error_detail(response: Any, body: str) -> str:
        """Extract an actionable error summary from a Mailjet error response body.

        Returns:
            str: Formatted error suffix (leading ': ...') or empty string.
        """
        error_detail = ""
        with suppress(Exception):
            resp_json = response.json()
            if isinstance(resp_json, dict):
                if "ErrorMessage" in resp_json:
                    error_detail = f": {resp_json['ErrorMessage']}"
                elif isinstance(messages := resp_json.get("Messages"), list) and messages:
                    first_msg = messages[0]
                    if (
                        isinstance(first_msg, dict)
                        and isinstance(errors := first_msg.get("Errors"), list)
                        and errors
                        and isinstance(errors[0], dict)
                    ):
                        error_detail = f": {errors[0].get('ErrorMessage', '')}"
        if not error_detail and body:
            error_detail = f": {body}"
        return error_detail

    @classmethod
    def _raise_mapped_http_error(cls, response: Any, exc: Exception) -> NoReturn:
        """Map an HTTP response status code to the Mailjet exception hierarchy."""
        status = int(response.status_code)
        body = str(getattr(response, "text", "") or "")
        error_detail = cls._extract_error_detail(response, body)

        if status in {401, 403}:
            msg = f"Authentication or Authorization failed{error_detail}"
            raise MailjetAuthError(msg, status, body) from exc
        if status == 429:
            msg = f"Rate limit exceeded{error_detail}"
            raise ApiRateLimitError(msg, status, body) from exc
        if status == 404:
            msg = f"Resource not found{error_detail}"
            raise DoesNotExistError(msg, status, body) from exc
        if status == 400:
            msg = f"Payload validation failed{error_detail}"
            raise ValidationError(msg, status, body) from exc
        if status >= 400:
            msg = f"Mailjet API HTTP {status}{error_detail}"
            raise MailjetApiError(msg, status, body) from exc

        msg = f"An unexpected Mailjet API network error occurred: {exc}"
        raise ApiError(msg) from exc

    @classmethod
    def _handle_api_error(cls, e: Exception) -> NoReturn:
        """Map transport or HTTP status exceptions to Mailjet specific API errors."""
        response = getattr(e, "response", None)
        if response is not None:
            cls._raise_mapped_http_error(response, e)

        msg = f"An unexpected Mailjet API network error occurred: {e}"
        raise ApiError(msg) from e

    def _apply_idempotency(self, data: PayloadType, req_headers: dict[str, str | None]) -> None:
        if any(k.lower() == "idempotency-key" for k in req_headers):
            return
        mode = getattr(self.config, "auto_idempotency_mode", "fingerprint")
        if mode == "off":
            return
        if mode == "uuid4":
            req_headers["Idempotency-Key"] = str(uuid.uuid4())
        elif isinstance(data, (dict, list)):
            req_headers["Idempotency-Key"] = SecurityGuard.generate_payload_fingerprint(data)

    def _prepare_api_call(
        self,
        method: HttpMethod,
        filters: dict[str, Any] | None,
        data: PayloadType,
        headers: Mapping[str, str | None] | None,
        timeout: TimeoutType,
        kwargs: dict[str, Any],
    ) -> tuple[dict[str, str | None], Any, dict[str, Any] | None, dict[str, Any]]:
        """Validate runtime URL, headers, TLS/redirect flags, timeout, kwargs, and idempotency.

        Returns:
            tuple[dict[str, str | None], Any, dict[str, Any] | None, dict[str, Any]]:
                Sanitized headers, validated timeout, stripped filters, and safe kwargs.
        """
        # Re-validate runtime config URL to prevent post-init SSRF mutations (HIGH-02)
        SecurityGuard.validate_config_url(self.config.api_url, allowed_root_domain=self.config.ALLOWED_ROOT_DOMAIN)

        # Ensure headers is a dictionary and screened for CRLF injections (CWE-113)
        req_headers: dict[str, str | None] = {} if headers is None else SecurityGuard.sanitize_headers(headers)

        SecurityGuard.resolve_tls_verify(kwargs.get("verify", self.config.verify))
        if kwargs.get("allow_redirects", False) is not False or kwargs.pop("follow_redirects", False) is not False:
            msg = "Redirects are strictly disabled (allow_redirects=True / follow_redirects=True is forbidden)."
            raise ValueError(msg)

        # Safely determine and validate active timeout bounds (CWE-400)
        active_timeout = timeout if timeout is not None else self.config.timeout
        try:
            req_timeout = SecurityGuard.validate_timeout(active_timeout)
        except (ValueError, TypeError):
            if timeout is None:
                # Self-heal corrupted runtime mutation on config.timeout
                self.config.timeout = _DEFAULT_TIMEOUT
            raise

        # Proxy Security Guardrail
        SecurityGuard.check_request_security(kwargs)

        # CWE-915: Prevent Mass Assignment of internal HTTP client states
        safe_kwargs = SecurityGuard.filter_safe_kwargs(kwargs)

        # Idempotency Lock for mutations
        if method.upper() in self._MUTATING_METHODS and not self.config.dry_run:
            self._apply_idempotency(data, req_headers)

        # Strip None filters
        clean_filters = {k: v for k, v in filters.items() if v is not None} if filters else None
        return req_headers, req_timeout, clean_filters, safe_kwargs

    @staticmethod
    def _check_unexpected_redirect(url: str, response: Any) -> None:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 300 <= status_code < 400:
            sys.audit("mailjet.security.unexpected_redirect", url, status_code)
            logger.warning("Unexpected HTTP redirect (%s) from %s; redirects are disabled.", status_code, url)

    @staticmethod
    def _log_request(method: str, url: str, response: Any, trace_str: str) -> None:
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
    def _extract_telemetry(data: Any, _headers: Mapping[str, str | None] | None) -> tuple[str, dict[str, str]]:
        """Extract tracing identifiers for safe logging and structured telemetry.

        Args:
            data (Any): The request payload.
            _headers (Mapping[str, str | None] | None): Request headers.

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


class Client(BaseClient):
    """The central synchronous Mailjet API client using requests.

    This class serves as the entry point for synchronous interactions with the Mailjet API.
    It manages the connection pool, handles retries, and dynamically resolves
    endpoint attributes based on the static routing registry.
    """

    __slots__ = ()
    _endpoint_cache: dict[str, Endpoint]
    _session: requests.Session | None

    def _build_session(self) -> requests.Session:
        resolved_verify = SecurityGuard.resolve_tls_verify(self.config.verify)
        session = requests.Session()
        session.verify = resolved_verify

        session.auth = self.auth if isinstance(self.auth, SecretAuth) else None
        if isinstance(self.auth, str):
            session.headers.update({"Authorization": f"Bearer {self.auth}"})

        session.headers.update({"User-Agent": self.config.user_agent})

        ca_bundle = resolved_verify if isinstance(resolved_verify, str) else None
        retry_strategy = (
            self._RETRY_STRATEGY
            if self.config.max_retries == 3
            else JitterRetry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=sorted(self._TRANSIENT_STATUS_CODES),
                allowed_methods=list(self._RETRY_ALLOWED_METHODS),
            )
        )
        adapter = SecureHTTPAdapter(
            ca_bundle=ca_bundle,
            pool_connections=self.config.pool_connections,
            pool_maxsize=self.config.pool_maxsize,
            max_retries=retry_strategy,
        )
        session.mount("https://", adapter)
        return session

    @property
    def session(self) -> requests.Session:
        """Lazily create and return the underlying thread-safe HTTP session.

        Returns:
            requests.Session: The configured session instance.
        """
        with self._lock:
            if self._session is None:
                if self._closed:
                    closed_session = requests.Session()
                    closed_session.auth = None
                    closed_session.headers.clear()
                    closed_session.close()
                    self._session = closed_session
                else:
                    self._session = self._build_session()
            return self._session

    @session.setter
    def session(self, value: requests.Session | None) -> None:
        with self._lock:
            self._session = value

    def __enter__(self) -> Self:
        """Enter the context manager and return the client instance.

        Returns:
            Self: The client instance.
        """
        with self._lock:
            if self._closed:
                self._closed = False
                self._session = None
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

    def close(self) -> None:
        """Secure resource teardown closing internal sockets."""
        with self._lock:
            self._closed = True
            session = self._session
            self._session = None
        if session is not None:
            try:
                session.auth = None
                session.headers.clear()
            finally:
                session.close()

    def __getattr__(self, name: str) -> Endpoint:
        """O(1) Route mapping returning a synchronous Endpoint instance.

        Returns:
            Endpoint: A dynamically created endpoint instance mapping to the route.
        """
        return self._resolve_endpoint(name, Endpoint)

    def _execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, Any],
        data: Any,
        params: Mapping[str, str | None] | None,
        timeout: Any,
        **kwargs: Any,
    ) -> requests.Response:
        """Isolated HTTP execution to reduce complexity and handle core network logic.

        Returns:
            requests.Response: The raw HTTP response directly from the network.
        """
        req_verify = SecurityGuard.resolve_tls_verify(kwargs.pop("verify", self.config.verify))
        allow_redirects = kwargs.pop("allow_redirects", False)
        if allow_redirects is not False:
            msg = "Redirects are strictly disabled (allow_redirects=True is forbidden)."
            raise ValueError(msg)

        files = kwargs.get("files")
        clean_headers = self._prepare_clean_headers(headers, files=files)

        content_type = clean_headers.get("Content-Type", "")
        is_json = not files and isinstance(data, (dict, list)) and "application/json" in content_type

        response = self.session.request(
            method=method,
            url=url,
            headers=clean_headers,
            json=data if is_json else None,
            data=data if not is_json else None,
            params=params,
            timeout=timeout,
            verify=req_verify,
            allow_redirects=False,
            **kwargs,
        )
        self._check_unexpected_redirect(url, response)
        return response

    def ping(self, timeout: TimeoutType = None) -> bool:
        """Verify Mailjet API reachability and credentials with a lightweight GET call.

        Args:
            timeout: Optional timeout override for the health check.

        Returns:
            bool: True if the API responds cleanly (< 400); False on API or network failures.
        """
        try:
            response = self.api_call("GET", self._ping_url(), filters={"Limit": 1}, timeout=timeout)
        except ApiError:
            return False
        else:
            return bool(response.status_code < 400)

    def api_call(  # ruff: ignore[complex-structure]
        self,
        method: HttpMethod,
        url: str,
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: Mapping[str, str | None] | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the authenticated API call with idempotency guards.

        Args:
            method (HttpMethod): The HTTP method.
            url (str): The fully constructed API URL.
            filters (dict[str, Any] | None, optional): Query parameters.
            data (PayloadType, optional): Request payload.
            headers (Mapping[str, str | None] | None, optional): Custom HTTP headers.
            timeout (TimeoutType, optional): Request timeout.
            **kwargs (Any): Additional arguments passed to 'requests.Session.request'.

        Returns:
            requests.Response: The authenticated HTTP response from Mailjet.
        """
        req_headers, req_timeout, clean_filters, safe_kwargs = self._prepare_api_call(
            method=method,
            filters=filters,
            data=data,
            headers=headers,
            timeout=timeout,
            kwargs=kwargs,
        )

        if method.upper() in self._MUTATING_METHODS and self.config.dry_run:
            logger.info("DRY RUN: Intercepted %s request to %s", method, url)
            mock = requests.Response()
            mock.status_code = 200
            return mock

        try:
            response = self._execute_request(
                method=method,
                url=url,
                headers=req_headers,
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
            if response.status_code in {200, 201, 204} and logger.isEnabledFor(logging.DEBUG):
                trace_suffix, _ = self._extract_telemetry(data, req_headers)
                self._log_request(method, url, response, trace_suffix)
            return response


class AsyncClient(BaseClient):
    """The asynchronous Mailjet API client backed strictly by httpx2.

    Provides async/await access to Mailjet REST resources with lazy session
    creation, TLS 1.2+ context caching, TCP keep-alive socket options, and
    strict redirect blocking.
    """

    __slots__ = ("_custom_transport",)
    _custom_transport: httpx2.AsyncBaseTransport | None
    _endpoint_cache: dict[str, AsyncEndpoint]
    _session: httpx2.AsyncClient | None

    def __init__(
        self,
        auth: str | tuple[str, str] | None = None,
        config: Config | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the asynchronous client (requires optional 'httpx2>=2.0.0').

        Args:
            auth: A tuple containing the Mailjet API key and secret, or a Bearer token string.
            config: An optional Config object for advanced behavior tuning.
            transport: Optional custom httpx2 async transport (e.g., MockTransport) for pooled requests.
            **kwargs: Configuration values (e.g., version, timeout) applied directly to a new Config object.
        """
        _require_httpx2()
        super().__init__(auth=auth, config=config, **kwargs)
        self._custom_transport = transport

    def _init_runtime_state(self) -> None:
        super()._init_runtime_state()
        self._custom_transport = None

    @staticmethod
    def _coerce_timeout(httpx2_mod: Any, timeout_val: Any) -> Any:
        if isinstance(timeout_val, tuple) and len(timeout_val) == 2:
            connect_t, read_t = float(timeout_val[0]), float(timeout_val[1])
            return httpx2_mod.Timeout(read_t, connect=connect_t, read=read_t, write=read_t, pool=connect_t)
        if isinstance(timeout_val, (int, float)) and not isinstance(timeout_val, bool):
            return httpx2_mod.Timeout(float(timeout_val))
        return timeout_val

    def _build_auth_and_headers(self) -> tuple[Any, dict[str, str]]:
        client_headers: dict[str, str] = {"User-Agent": self.config.user_agent}
        httpx2_auth: Any = None
        if isinstance(self.auth, str):
            client_headers["Authorization"] = f"Bearer {self.auth}"
        elif isinstance(self.auth, SecretAuth):
            auth_header = self.auth.auth_header

            def _apply_secret_auth(request: Any) -> Any:
                request.headers["Authorization"] = auth_header
                return request

            httpx2_auth = _apply_secret_auth
        return httpx2_auth, client_headers

    def _build_transport(
        self,
        httpx2_mod: Any,
        resolved_verify: bool | str,
        *,
        proxy: Any = None,
        cert: Any = None,
    ) -> httpx2.AsyncHTTPTransport:
        ca_bundle = resolved_verify if isinstance(resolved_verify, str) else None
        ssl_ctx = (
            build_ssl_context_with_cert(ca_bundle, cert) if cert is not None else get_secure_ssl_context(ca_bundle)
        )
        limits = httpx2_mod.Limits(
            max_connections=self.config.pool_maxsize,
            max_keepalive_connections=self.config.pool_connections,
        )
        transport: httpx2.AsyncHTTPTransport = httpx2_mod.AsyncHTTPTransport(
            verify=ssl_ctx,
            limits=limits,
            proxy=proxy,
            retries=0,
            socket_options=_KEEPALIVE_SOCKET_OPTIONS,
        )
        return transport

    def _build_session(self) -> httpx2.AsyncClient:
        httpx2_mod = _require_httpx2()
        resolved_verify = SecurityGuard.resolve_tls_verify(self.config.verify)
        validated_timeout = SecurityGuard.validate_timeout(self.config.timeout)
        auth_obj, client_headers = self._build_auth_and_headers()
        transport: httpx2.AsyncBaseTransport = (
            self._custom_transport
            if self._custom_transport is not None
            else self._build_transport(httpx2_mod, resolved_verify)
        )
        session: httpx2.AsyncClient = httpx2_mod.AsyncClient(
            auth=auth_obj,
            headers=client_headers,
            timeout=self._coerce_timeout(httpx2_mod, validated_timeout),
            follow_redirects=False,
            transport=transport,
        )
        return session

    @property
    def session(self) -> httpx2.AsyncClient:
        """Lazily create and return the underlying thread-safe async HTTP client.

        Returns:
            httpx2.AsyncClient: The configured async client instance.
        """
        with self._lock:
            if self._closed:
                if self._session is None or getattr(self._session, "is_closed", False):
                    httpx2_mod = _require_httpx2()
                    closed_session: httpx2.AsyncClient = httpx2_mod.AsyncClient(follow_redirects=False)
                    closed_session.auth = None
                    closed_session.headers.clear()
                    self._session = closed_session
                return self._session
            if self._session is None or getattr(self._session, "is_closed", False):
                self._session = self._build_session()
            return self._session

    @session.setter
    def session(self, value: httpx2.AsyncClient | None) -> None:
        with self._lock:
            self._session = value

    async def __aenter__(self) -> Self:
        """Enter the async context manager and return the AsyncClient instance.

        Returns:
            Self: The AsyncClient instance.
        """
        stale_session: httpx2.AsyncClient | None = None
        with self._lock:
            if self._closed:
                self._closed = False
                stale_session = self._session
                self._session = None
        if stale_session is not None and not getattr(stale_session, "is_closed", False):
            await stale_session.aclose()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the async context manager and safely close the async HTTP client."""
        await self.aclose()

    async def aclose(self) -> None:
        """Secure asynchronous resource teardown closing internal sockets."""
        with self._lock:
            self._closed = True
            session = self._session
            self._session = None
        if session is not None:
            try:
                session.auth = None
                session.headers.clear()
            finally:
                await session.aclose()

    async def close(self) -> None:
        """Alias for aclose() providing consistent teardown ergonomics."""
        await self.aclose()

    def __getattr__(self, name: str) -> AsyncEndpoint:
        """O(1) Route mapping returning an AsyncEndpoint instance.

        Returns:
            AsyncEndpoint: A dynamically created asynchronous endpoint instance mapping to the route.
        """
        return self._resolve_endpoint(name, AsyncEndpoint)

    async def _request_isolated(
        self,
        httpx2_mod: Any,
        req_verify: bool | str,
        proxies: Any,
        cert: Any,
        req_kwargs: dict[str, Any],
    ) -> httpx2.Response:
        proxy_url = proxies.get("https") or proxies.get("http") if isinstance(proxies, Mapping) else proxies
        auth_obj, base_headers = self._build_auth_and_headers()
        transport = self._build_transport(httpx2_mod, req_verify, proxy=proxy_url, cert=cert)
        async with httpx2_mod.AsyncClient(
            auth=auth_obj,
            headers=base_headers,
            follow_redirects=False,
            transport=transport,
        ) as ephemeral_session:
            response: httpx2.Response = await ephemeral_session.request(**req_kwargs)
            return response

    async def _send_once(
        self,
        httpx2_mod: Any,
        isolated: bool,
        req_verify: bool | str,
        proxies: Any,
        cert: Any,
        req_kwargs: dict[str, Any],
    ) -> httpx2.Response:
        if isolated:
            return await self._request_isolated(httpx2_mod, req_verify, proxies, cert, req_kwargs)
        response: httpx2.Response = await self.session.request(**req_kwargs)
        return response

    async def _send_with_retries(  # ruff: ignore[complex-structure]
        self,
        httpx2_mod: Any,
        isolated: bool,
        req_verify: bool | str,
        proxies: Any,
        cert: Any,
        req_kwargs: dict[str, Any],
        data: Any,
        files: Any,
    ) -> httpx2.Response:
        max_retries = self.config.max_retries
        retryable_errors: tuple[type[Exception], ...] = (
            httpx2_mod.TimeoutException,
            httpx2_mod.NetworkError,
            httpx2_mod.RemoteProtocolError,
            httpx2_mod.ProxyError,
        )
        method = str(req_kwargs.get("method", "GET")).upper()
        url = str(req_kwargs.get("url", ""))

        for attempt in range(max_retries + 1):
            try:
                response = await self._send_once(httpx2_mod, isolated, req_verify, proxies, cert, req_kwargs)
            except (httpx2_mod.UnsupportedProtocol, httpx2_mod.DecodingError):
                raise
            except retryable_errors as exc:
                if attempt >= max_retries:
                    raise
                delay = self._compute_retry_delay(attempt)
                logger.warning(
                    "Transient async transport error (%s) on %s %s; retry %d/%d in %.2fs",
                    type(exc).__name__,
                    method,
                    url,
                    attempt + 1,
                    max_retries,
                    delay,
                )
            else:
                status = getattr(response, "status_code", None)
                if attempt >= max_retries or status not in self._TRANSIENT_STATUS_CODES:
                    return response
                resp_headers = getattr(response, "headers", None)
                retry_after = (
                    resp_headers.get("Retry-After") or resp_headers.get("retry-after")
                    if resp_headers is not None
                    else None
                )
                delay = self._compute_retry_delay(attempt, retry_after)
                logger.warning(
                    "Transient HTTP %s on %s %s; retry %d/%d in %.2fs",
                    status,
                    method,
                    url,
                    attempt + 1,
                    max_retries,
                    delay,
                )
                if not getattr(response, "is_closed", True):
                    with suppress(Exception):
                        await response.aclose()

            await asyncio.sleep(delay)
            self._reset_stream_pointers(data, files)

        msg = "Retry loop exited unexpectedly."  # pragma: no cover
        raise CriticalApiError(msg)  # pragma: no cover

    async def _execute_request(
        self,
        method: str,
        url: str,
        headers: dict[str, Any],
        data: Any,
        params: Mapping[str, Any] | None,
        timeout: Any,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Execute the underlying asynchronous HTTP request via httpx2.

        Returns:
            httpx2.Response: The raw HTTP response directly from the network.
        """
        httpx2_mod = _require_httpx2()
        default_verify = SecurityGuard.resolve_tls_verify(self.config.verify)
        req_verify = SecurityGuard.resolve_tls_verify(kwargs.pop("verify", self.config.verify))
        if kwargs.pop("allow_redirects", False) is not False or kwargs.pop("follow_redirects", False) is not False:
            msg = "Redirects are strictly disabled (allow_redirects=True / follow_redirects=True is forbidden)."
            raise ValueError(msg)

        proxies = kwargs.pop("proxies", None)
        cert = kwargs.pop("cert", None)
        if kwargs.pop("stream", False):
            msg = "stream=True is not supported on AsyncClient.api_call(); use endpoint.stream()."
            raise ValueError(msg)

        files = kwargs.get("files")
        clean_headers = self._prepare_clean_headers(headers, files=files)
        is_json = (
            not files and isinstance(data, (dict, list)) and "application/json" in clean_headers.get("Content-Type", "")
        )
        req_kwargs: dict[str, Any] = {
            "method": method,
            "url": url,
            "headers": clean_headers,
            "params": params,
            "timeout": self._coerce_timeout(httpx2_mod, timeout),
            **kwargs,
        }
        if is_json:
            req_kwargs["json"] = data
        elif files and isinstance(data, Mapping):
            req_kwargs["data"] = data
        elif data is not None:
            req_kwargs["content"] = data

        isolated = req_verify != default_verify or proxies is not None or cert is not None
        response = await self._send_with_retries(
            httpx2_mod=httpx2_mod,
            isolated=isolated,
            req_verify=req_verify,
            proxies=proxies,
            cert=cert,
            req_kwargs=req_kwargs,
            data=data,
            files=files,
        )

        self._check_unexpected_redirect(url, response)
        return response

    async def api_call(  # ruff: ignore[complex-structure]
        self,
        method: HttpMethod,
        url: str,
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: Mapping[str, str | None] | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Execute the authenticated asynchronous API call with idempotency guards.

        Args:
            method: The HTTP method.
            url: The fully constructed API URL.
            filters: Query parameters.
            data: Request payload.
            headers: Custom HTTP headers.
            timeout: Request timeout.
            **kwargs: Additional arguments passed to the async session request.

        Returns:
            httpx2.Response: The authenticated HTTP response from Mailjet.
        """
        httpx2_mod = _require_httpx2()
        req_headers, req_timeout, clean_filters, safe_kwargs = self._prepare_api_call(
            method=method,
            filters=filters,
            data=data,
            headers=headers,
            timeout=timeout,
            kwargs=kwargs,
        )

        if method.upper() in self._MUTATING_METHODS and self.config.dry_run:
            logger.info("DRY RUN: Intercepted %s request to %s", method, url)
            dry_resp: httpx2.Response = httpx2_mod.Response(
                status_code=200,
                request=httpx2_mod.Request(method.upper(), url),
            )
            return dry_resp

        try:
            response = await self._execute_request(
                method=method,
                url=url,
                headers=req_headers,
                data=data,
                params=clean_filters,
                timeout=req_timeout,
                **safe_kwargs,
            )
            if not isinstance(getattr(response, "status_code", None), int) or response.status_code >= 400:
                response.raise_for_status()

        except httpx2_mod.TimeoutException as e:
            logger.exception("Timeout Error: %s %s", method, url)
            msg = f"Request to Mailjet API timed out: {e}"
            raise TimeoutError(msg) from e

        except (
            httpx2_mod.ConnectError,
            httpx2_mod.NetworkError,
            httpx2_mod.RemoteProtocolError,
            httpx2_mod.ProxyError,
        ) as e:
            msg = f"Connection to Mailjet API failed: {e}"
            raise CriticalApiError(msg) from e

        except httpx2_mod.HTTPError as e:
            self._handle_api_error(e)

        else:
            if response.status_code in {200, 201, 204} and logger.isEnabledFor(logging.DEBUG):
                trace_suffix, _ = self._extract_telemetry(data, req_headers)
                self._log_request(method, url, response, trace_suffix)
            return response

    async def ping(self, timeout: TimeoutType = None) -> bool:
        """Verify Mailjet API reachability and credentials with a lightweight GET call.

        Args:
            timeout: Optional timeout override for the health check.

        Returns:
            bool: True if the API responds cleanly (< 400); False on API or network failures.
        """
        try:
            response = await self.api_call("GET", self._ping_url(), filters={"Limit": 1}, timeout=timeout)
        except ApiError:
            return False
        else:
            return bool(response.status_code < 400)


# --- Deprecated Wrappers ---
def parse_response(response: requests.Response | httpx2.Response) -> Any:
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
