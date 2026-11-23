"""Mailjet API v3, v3.1, v1, and v4 Python wrapper.

Provides synchronous (:class:`Client` via ``requests``) and asynchronous
(:class:`AsyncClient` via ``httpx2``) clients with unified security guardrails,
dynamic endpoint resolution, retries, and clean resource teardown.
"""

from __future__ import annotations

import copy
import importlib
import logging
import sys
import threading
import uuid
import warnings
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Any, ClassVar, Final, NoReturn, TypeVar

import requests
from requests.exceptions import ConnectionError as RequestsConnectionError, RequestException, Timeout as RequestsTimeout

from mailjet_rest.config import Config
from mailjet_rest.errors import (
    MAX_ERROR_DETAIL_CHARS,
    MAX_ERROR_LOG_CHARS,
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
    extract_error_detail,
    handle_api_error,
    raise_connection_error,
    raise_timeout_error,
)
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _DEFAULT_TIMEOUT
from mailjet_rest.utils.guardrails import RedactingFilter, SecretAuth, SecureHTTPAdapter, SecurityGuard
from mailjet_rest.utils.retry import (
    DEFAULT_RETRY_STRATEGY,
    MAX_RETRY_DELAY,
    RETRY_ALLOWED_METHODS,
    TRANSIENT_STATUS_CODES,
    JitterRetry,
    compute_retry_delay,
    reset_stream_pointers,
    run_async_with_retries,
)
from mailjet_rest.utils.telemetry import extract_telemetry, log_api_response
from mailjet_rest.utils.transport_security import build_httpx2_transport, coerce_httpx2_timeout


if TYPE_CHECKING:
    from collections.abc import Callable
    from types import TracebackType

    import httpx2

    from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
    from mailjet_rest.types import (
        AuthCredentials,
        CertConfig,
        HeadersMapping,
        HttpMethod,
        PayloadType,
        QueryFilters,
        RequestHeaders,
        TimeoutType,
    )

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
    "JitterRetry",
    "MailjetApiError",
    "MailjetAuthError",
    "TimeoutError",
    "ValidationError",
    "logging_handler",
    "parse_response",
]


logger = logging.getLogger(__name__)
if not any(isinstance(f, RedactingFilter) for f in logger.filters):
    logger.addFilter(RedactingFilter())

_EndpointT = TypeVar("_EndpointT")
_AVAILABLE_ENDPOINTS: Final[tuple[str, ...]] = tuple(sorted(ROUTE_MAP))
_DRY_RUN_BODY: Final[bytes] = b'{"DryRun":true,"Count":0,"Total":0,"Data":[],"Messages":[]}'
_httpx2_cache: list[Any] = []


def _get_httpx2() -> Any:
    if not _httpx2_cache:
        try:
            mod = importlib.import_module("httpx2")
        except ImportError:
            return None
        _httpx2_cache.append(mod)
    return _httpx2_cache[0]


def _require_httpx2() -> Any:
    mod = globals()["_httpx2"] if "_httpx2" in globals() else _get_httpx2()
    if mod is None:
        msg = "AsyncClient requires 'httpx2>=2.0.0'. Install with: pip install 'mailjet-rest[async]'"
        raise ImportError(msg)
    return mod


def _resolve_proxy_url(proxies: Any) -> str | None:
    """Resolve an HTTP/HTTPS proxy URL case-insensitively from str or proxy mappings.

    Returns:
        str | None: Selected proxy URL or None when absent.
    """
    if proxies is None:
        return None
    if isinstance(proxies, str):
        return proxies
    if isinstance(proxies, Mapping):
        lowered = {str(k).lower().rstrip("/"): v for k, v in proxies.items() if v is not None}
        for key in ("https:", "https", "all:", "all", "http:", "http"):
            if key in lowered:
                return str(lowered[key])
        if lowered:
            msg = f"Unsupported proxy mapping keys {sorted(proxies.keys())!r}; expected 'https' or 'http'."
            raise ValueError(msg)
    return None


def __getattr__(name: str) -> Any:
    """Resolve optional ``_httpx2`` and legacy module-level symbols lazily.

    Returns:
        Any: Imported module/symbol when supported.
    """
    if name == "_httpx2":
        return _get_httpx2()
    if name in {"AsyncEndpoint", "BaseEndpoint", "Endpoint"}:
        from mailjet_rest.endpoint import (  # ruff: ignore[import-outside-top-level]
            AsyncEndpoint,
            BaseEndpoint,
            Endpoint,
        )

        return {"AsyncEndpoint": AsyncEndpoint, "BaseEndpoint": BaseEndpoint, "Endpoint": Endpoint}[name]
    if name == "Retry":
        from urllib3.util.retry import Retry  # ruff: ignore[import-outside-top-level]

        globals()[name] = Retry
        return Retry
    if name == "_ALLOWED_TRACE_FIELDS":
        from mailjet_rest.types import _ALLOWED_TRACE_FIELDS  # ruff: ignore[import-outside-top-level]

        globals()[name] = _ALLOWED_TRACE_FIELDS
        return _ALLOWED_TRACE_FIELDS
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)


class BaseClient:
    """Shared configuration, TLS policy, request validation, telemetry, and error mapping."""

    __slots__ = ("_closed", "_endpoint_cache", "_lock", "_session", "auth", "config")

    _MUTATING_METHODS: ClassVar[frozenset[str]] = frozenset({"POST", "PUT", "PATCH", "DELETE"})
    _TRANSIENT_STATUS_CODES: ClassVar[frozenset[int]] = TRANSIENT_STATUS_CODES
    _MAX_RETRY_DELAY: ClassVar[float] = MAX_RETRY_DELAY
    _MAX_ERROR_LOG_CHARS: ClassVar[int] = MAX_ERROR_LOG_CHARS
    _MAX_ERROR_DETAIL_CHARS: ClassVar[int] = MAX_ERROR_DETAIL_CHARS
    _RETRY_ALLOWED_METHODS: ClassVar[tuple[str, ...]] = RETRY_ALLOWED_METHODS
    _RETRY_STRATEGY: ClassVar[JitterRetry] = DEFAULT_RETRY_STRATEGY
    _closed: bool
    _endpoint_cache: Any
    _lock: threading.RLock
    _session: Any
    auth: str | SecretAuth | None
    config: Config

    def __init__(
        self,
        auth: AuthCredentials = None,
        config: Config | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize client configuration, TLS verification, and API credentials."""
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
        self.auth = SecurityGuard.validate_and_coerce_auth(auth)

        if getattr(self.config, "enable_security_audit", False):
            SecurityGuard.enable_audit_logging()

    @property
    def available_endpoints(self) -> tuple[str, ...]:
        """Sorted names of all statically registered Mailjet API endpoints.

        Returns:
            tuple[str, ...]: Registered endpoint attribute names.
        """
        return _AVAILABLE_ENDPOINTS

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
        """Create a shallow copy with an isolated uninitialized HTTP session state.

        Returns:
            Self: New client instance sharing configuration without open sockets.
        """
        return self._clone()

    def __deepcopy__(self, memo: dict[int, Any]) -> Self:
        """Create a deep copy with an isolated uninitialized HTTP session state.

        Returns:
            Self: Deeply copied client instance with fresh runtime session state.
        """
        return self._clone(memo)

    def __repr__(self) -> str:
        """Return a redacted representation safe for logs and tracebacks.

        Returns:
            str: Sanitized client description.
        """
        return f"<{self.__class__.__name__} API Version='{self.config.version}' URL='{self.config.api_url}'>"

    def __str__(self) -> str:
        """Return a concise redacted string representation.

        Returns:
            str: Sanitized client label.
        """
        return f"Mailjet {self.__class__.__name__} ({self.config.version})"

    def __dir__(self) -> list[str]:
        """Expose dynamic routing attributes for interactive completion and inspection.

        Returns:
            list[str]: Standard attributes merged with statically registered route names.
        """
        return sorted({*super().__dir__(), *_AVAILABLE_ENDPOINTS})

    def _validate_endpoint_name(self, name: str) -> None:
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

        if "_" not in name and name not in ROUTE_MAP:
            import difflib  # ruff: ignore[import-outside-top-level]

            if matches := difflib.get_close_matches(name, dir(self), n=1, cutoff=0.8):
                msg = f"'{self.__class__.__name__}' has no endpoint or attribute '{name}'. Did you mean '{matches[0]}'?"
                raise AttributeError(msg)

    def _resolve_via_loader(self, name: str, loader: Callable[[], type[_EndpointT]]) -> _EndpointT:
        if not name.startswith("_"):
            cached: _EndpointT | None = self._endpoint_cache.get(name)
            if cached is not None:
                return cached
        if sys.meta_path is None:
            raise AttributeError(name)
        return self._resolve_endpoint(name, loader())

    def _detach_session_for_close(self) -> Any:
        with self._lock:
            self._closed = True
            session = self._session
            self._session = None
        if session is not None:
            session.auth = None
            session.headers.clear()
        return session

    def _close_sync_session(self) -> None:
        session = self._detach_session_for_close()
        if session is not None:
            session.close()

    def _resolve_endpoint(self, name: str, endpoint_cls: type[_EndpointT]) -> _EndpointT:
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)

        with self._lock:
            if name in self._endpoint_cache:
                cached: _EndpointT = self._endpoint_cache[name]
                return cached

        self._validate_endpoint_name(name)
        ctor: Any = endpoint_cls
        with self._lock:
            resolved: _EndpointT = self._endpoint_cache.setdefault(
                name,
                ctor(client=self, name=name),
            )
            return resolved

    def _base_headers(self) -> dict[str, str]:
        headers = {"User-Agent": self.config.user_agent}
        if isinstance(self.auth, str):
            headers["Authorization"] = f"Bearer {self.auth}"
        return headers

    def _ping_url(self) -> str:
        return f"{self.config.api_url.rstrip('/')}/v3/REST/apikey"

    def _warn_if_unclosed(self) -> None:
        try:
            closed = self._closed
            session = self._session
            config = self.config
        except AttributeError:
            return

        if closed or session is None or not config.warn_unclosed:
            return

        if isinstance(self, AsyncClient):
            msg = "Unclosed Mailjet AsyncClient session; call await client.aclose() or use 'async with'."
        else:
            msg = "Unclosed Mailjet Client session; call client.close() or use a context manager."
        warnings.warn(msg, ResourceWarning, stacklevel=3)

    def __del__(self) -> None:
        """Emit an opt-in ResourceWarning when an opened session was not closed."""
        self._warn_if_unclosed()

    @classmethod
    def _compute_retry_delay(cls, attempt: int, retry_after_header: str | None = None) -> float:
        return compute_retry_delay(attempt, retry_after_header, max_delay=cls._MAX_RETRY_DELAY)

    @staticmethod
    def _reset_stream_pointers(data: Any, files: Any) -> None:
        reset_stream_pointers(data, files)

    @classmethod
    def _extract_error_detail(cls, response: Any, body: str) -> str:
        return extract_error_detail(response, body, max_chars=cls._MAX_ERROR_DETAIL_CHARS)

    @classmethod
    def _handle_api_error(cls, e: Exception) -> NoReturn:
        handle_api_error(e, max_chars=cls._MAX_ERROR_DETAIL_CHARS)

    @staticmethod
    def _log_request(method: str, url: str, response: Any, trace_str: str) -> None:
        log_api_response(logger, method, url, response, trace_str, max_chars=BaseClient._MAX_ERROR_LOG_CHARS)

    @staticmethod
    def _extract_telemetry(data: Any, _headers: HeadersMapping | None) -> tuple[str, dict[str, str]]:
        return extract_telemetry(data, _headers)

    def _record_success_telemetry(
        self,
        method: str,
        url: str,
        response: Any,
        data: Any,
        headers: HeadersMapping | None,
    ) -> None:
        if getattr(response, "status_code", None) not in {200, 201, 204}:
            return
        cls = type(self)
        has_custom_hook = (
            cls._log_request is not BaseClient._log_request
            or cls._extract_telemetry is not BaseClient._extract_telemetry
        )
        if has_custom_hook or logger.isEnabledFor(logging.DEBUG):
            trace_suffix, _ = self._extract_telemetry(data, headers)
            self._log_request(method, url, response, trace_suffix)

    @staticmethod
    def _prepare_clean_headers(headers: Mapping[str, Any], files: Any = None) -> dict[str, Any]:
        if files is not None:
            SecurityGuard.validate_multipart_files(files)
        clean_headers = {k: v for k, v in headers.items() if v is not None}
        if files:
            for key in list(clean_headers):
                val = clean_headers[key]
                if key.lower() == "content-type" and isinstance(val, str) and val.strip().lower() == "application/json":
                    del clean_headers[key]
        return clean_headers

    @staticmethod
    def _check_unexpected_redirect(url: str, response: Any) -> None:
        status_code = getattr(response, "status_code", None)
        if isinstance(status_code, int) and 300 <= status_code < 400 and status_code != 304:
            sys.audit("mailjet.security.unexpected_redirect", url, status_code)
            logger.warning("Unexpected HTTP redirect (%s) from %s; redirects are disabled.", status_code, url)

    def _apply_idempotency(
        self,
        data: PayloadType,
        req_headers: RequestHeaders,
        *,
        method: str = "",
        url: str = "",
    ) -> None:
        if any(k.lower() == "idempotency-key" for k in req_headers):
            return
        mode = getattr(self.config, "auto_idempotency_mode", "fingerprint")
        if mode == "off":
            return
        if mode == "uuid4":
            req_headers["Idempotency-Key"] = str(uuid.uuid4())
        elif isinstance(data, (Mapping, list)):
            fingerprint_input: Any = {"m": method.upper(), "u": url, "d": data} if (method or url) else data
            req_headers["Idempotency-Key"] = SecurityGuard.generate_payload_fingerprint(fingerprint_input)

    def _resolve_call_timeout(self, timeout: TimeoutType) -> Any:
        active_timeout = timeout if timeout is not None else self.config.timeout
        try:
            return SecurityGuard.validate_timeout(active_timeout)
        except (ValueError, TypeError):
            if timeout is None:
                self.config.timeout = _DEFAULT_TIMEOUT
            raise

    @staticmethod
    def _assert_redirects_disabled(kwargs: dict[str, Any]) -> None:
        if kwargs.get("allow_redirects", False) is not False or kwargs.pop("follow_redirects", False) is not False:
            msg = "Redirects are strictly disabled (allow_redirects=True / follow_redirects=True is forbidden)."
            raise ValueError(msg)

    def _prepare_api_call(
        self,
        method: HttpMethod,
        url: str,
        filters: QueryFilters | None,
        data: PayloadType,
        headers: HeadersMapping | None,
        timeout: TimeoutType,
        kwargs: dict[str, Any],
    ) -> tuple[RequestHeaders, Any, dict[str, Any] | None, dict[str, Any]]:
        SecurityGuard.validate_target_url(
            url,
            base_api_url=self.config.api_url,
            allowed_root_domain=self.config.ALLOWED_ROOT_DOMAIN,
        )
        req_headers: RequestHeaders = {} if headers is None else SecurityGuard.sanitize_headers(headers)

        SecurityGuard.resolve_tls_verify(kwargs.get("verify", self.config.verify))
        self._assert_redirects_disabled(kwargs)
        req_timeout = self._resolve_call_timeout(timeout)

        SecurityGuard.check_request_security(kwargs)
        safe_kwargs = SecurityGuard.filter_safe_kwargs(kwargs)

        if method.upper() in self._MUTATING_METHODS and not self.config.dry_run:
            self._apply_idempotency(data, req_headers, method=method, url=url)

        clean_filters = {k: v for k, v in filters.items() if v is not None} if filters else None
        return req_headers, req_timeout, clean_filters, safe_kwargs

    def _normalize_request_parts(
        self,
        headers: Mapping[str, Any],
        data: Any,
        kwargs: dict[str, Any],
    ) -> tuple[bool | str, dict[str, Any], bool, Any, Any]:
        req_verify = SecurityGuard.resolve_tls_verify(kwargs.pop("verify", self.config.verify))
        if kwargs.pop("allow_redirects", False) is not False or kwargs.pop("follow_redirects", False) is not False:
            msg = "Redirects are strictly disabled (allow_redirects=True / follow_redirects=True is forbidden)."
            raise ValueError(msg)

        files = kwargs.get("files")
        clean_headers = self._prepare_clean_headers(headers, files=files)
        content_type = next(
            (v for k, v in clean_headers.items() if k.lower() == "content-type" and isinstance(v, str)),
            "",
        )
        ct_lower = content_type.lower()
        is_json = (
            not files and isinstance(data, (Mapping, list)) and ("application/json" in ct_lower or "+json" in ct_lower)
        )
        normalized_data = dict(data) if isinstance(data, Mapping) and not isinstance(data, dict) else data
        return req_verify, clean_headers, is_json, normalized_data, files


class Client(BaseClient):
    """Synchronous Mailjet API client backed by ``requests.Session``."""

    __slots__ = ()
    _endpoint_cache: dict[str, Endpoint]
    _session: requests.Session | None

    def _build_session(self) -> requests.Session:
        resolved_verify = SecurityGuard.resolve_tls_verify(self.config.verify)
        session = requests.Session()
        session.trust_env = self.config.trust_env
        session.verify = resolved_verify
        session.auth = self.auth if isinstance(self.auth, SecretAuth) else None
        session.headers.update(self._base_headers())

        ca_bundle = resolved_verify if isinstance(resolved_verify, str) else None
        retry_strategy = (
            self._RETRY_STRATEGY
            if self.config.max_retries == 3
            else JitterRetry(
                total=self.config.max_retries,
                backoff_factor=1,
                status_forcelist=sorted(self._TRANSIENT_STATUS_CODES),
                allowed_methods=list(self._RETRY_ALLOWED_METHODS),
                raise_on_status=False,
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
        """Lazily create and return the thread-safe synchronous ``requests.Session``.

        Returns:
            requests.Session: Configured HTTP session, or a credential-stripped closed session.
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
        """Enter the context manager and reset closed session state if re-entered.

        Returns:
            Self: The active synchronous client instance.
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
        """Exit the context manager and tear down open HTTP sockets."""
        _ = (exc_type, exc_val, exc_tb)
        self.close()

    def close(self) -> None:
        """Clear credential headers and close the underlying ``requests.Session``."""
        self._close_sync_session()

    def __getattr__(self, name: str) -> Endpoint:
        """Resolve and cache a synchronous :class:`Endpoint` wrapper by route name.

        Returns:
            Endpoint: Cached or newly created synchronous endpoint wrapper.
        """
        if not name.startswith("_"):
            cached = self._endpoint_cache.get(name)
            if cached is not None:
                return cached
        if sys.meta_path is None:
            raise AttributeError(name)
        ep_cls: type[Endpoint] | None = globals().get("Endpoint")
        if ep_cls is None:
            from mailjet_rest.endpoint import Endpoint  # ruff: ignore[import-outside-top-level]

            ep_cls = Endpoint

        return self._resolve_endpoint(name, ep_cls)

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
        req_verify, clean_headers, is_json, normalized_data, _ = self._normalize_request_parts(headers, data, kwargs)
        response = self.session.request(
            method=method,
            url=url,
            headers=clean_headers,
            json=normalized_data if is_json else None,
            data=None if is_json else normalized_data,
            params=params,
            timeout=timeout,
            verify=req_verify,
            allow_redirects=False,
            **kwargs,
        )
        self._check_unexpected_redirect(url, response)
        return response

    def ping(self, timeout: TimeoutType = None) -> bool:
        """Verify Mailjet API reachability and credentials with a lightweight GET probe.

        Returns:
            bool: True when the API responds cleanly (< 400); False on API or network error.
        """
        try:
            response = self.api_call("GET", self._ping_url(), filters={"Limit": 1}, timeout=timeout)
        except ApiError:
            return False
        return bool(response.status_code < 400)

    def api_call(
        self,
        method: HttpMethod,
        url: str,
        filters: QueryFilters | None = None,
        data: PayloadType = None,
        headers: HeadersMapping | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute an authenticated synchronous API call with SSRF and idempotency guards.

        Returns:
            requests.Response: Raw synchronous HTTP response from Mailjet.
        """
        req_headers, req_timeout, clean_filters, safe_kwargs = self._prepare_api_call(
            method=method,
            url=url,
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
            mock._content = _DRY_RUN_BODY  # ruff: ignore[private-member-access]
            mock.encoding = "utf-8"
            mock.headers["Content-Type"] = "application/json"
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
            raise_timeout_error(logger, method, url, e)
        except RequestsConnectionError as e:
            raise_connection_error(e)
        except RequestException as e:
            self._handle_api_error(e)
        else:
            self._record_success_telemetry(method, url, response, data, req_headers)
            return response


class AsyncClient(BaseClient):
    """Asynchronous Mailjet API client backed strictly by ``httpx2``."""

    __slots__ = ("_custom_transport",)
    _custom_transport: httpx2.AsyncBaseTransport | None
    _endpoint_cache: dict[str, AsyncEndpoint]
    _session: httpx2.AsyncClient | None

    def __init__(
        self,
        auth: AuthCredentials = None,
        config: Config | None = None,
        transport: httpx2.AsyncBaseTransport | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize the asynchronous client (requires optional ``httpx2>=2.0.0``)."""
        _require_httpx2()
        super().__init__(auth=auth, config=config, **kwargs)
        self._custom_transport = transport

    def _init_runtime_state(self) -> None:
        super()._init_runtime_state()
        self._custom_transport = None

    @staticmethod
    def _coerce_timeout(httpx2_mod: Any, timeout_val: Any) -> Any:
        return coerce_httpx2_timeout(httpx2_mod, timeout_val)

    def _build_auth_and_headers(self) -> tuple[Any, dict[str, str]]:
        client_headers = self._base_headers()
        httpx2_auth: Any = None
        if isinstance(self.auth, SecretAuth):
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
        cert: CertConfig = None,
    ) -> httpx2.AsyncHTTPTransport:
        return build_httpx2_transport(
            httpx2_mod,
            resolved_verify,
            pool_connections=self.config.pool_connections,
            pool_maxsize=self.config.pool_maxsize,
            proxy=proxy,
            cert=cert,
        )

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
            trust_env=self.config.trust_env,
            transport=transport,
        )
        return session

    @property
    def session(self) -> httpx2.AsyncClient:
        """Lazily create and return the underlying thread-safe ``httpx2.AsyncClient``.

        Returns:
            httpx2.AsyncClient: Active async client, or a stripped closed placeholder when closed.
        """
        with self._lock:
            if self._closed:
                if self._session is None:
                    httpx2_mod = _require_httpx2()
                    closed_session: httpx2.AsyncClient = httpx2_mod.AsyncClient(
                        follow_redirects=False,
                        trust_env=False,
                        transport=httpx2_mod.AsyncBaseTransport(),
                    )
                    closed_session.auth = None
                    closed_session.headers.clear()
                    client_state = getattr(getattr(httpx2_mod, "_client", None), "ClientState", None)
                    if client_state is not None:
                        with suppress(AttributeError):
                            closed_session._state = client_state.CLOSED  # ruff: ignore[private-member-access]
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
        """Enter the async context manager and clear stale closed sessions on re-entry.

        Returns:
            Self: The active asynchronous client instance.
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
        """Exit the async context manager and close the underlying ``httpx2.AsyncClient``."""
        _ = (exc_type, exc_val, exc_tb)
        await self.aclose()

    async def aclose(self) -> None:
        """Clear credential headers and close the underlying async connection pool."""
        session = self._detach_session_for_close()
        if session is not None:
            await session.aclose()

    async def close(self) -> None:
        """Alias for :meth:`aclose` providing symmetric teardown ergonomics."""
        await self.aclose()

    @staticmethod
    def _load_async_endpoint_cls() -> type[AsyncEndpoint]:
        aep_cls: type[AsyncEndpoint] | None = globals().get("AsyncEndpoint")
        if aep_cls is not None:
            return aep_cls
        from mailjet_rest.endpoint import AsyncEndpoint  # ruff: ignore[import-outside-top-level]

        return AsyncEndpoint

    def __getattr__(self, name: str) -> AsyncEndpoint:
        """Resolve and cache an asynchronous :class:`AsyncEndpoint` wrapper by route name.

        Returns:
            AsyncEndpoint: Cached or newly created asynchronous endpoint wrapper.
        """
        return self._resolve_via_loader(name, self._load_async_endpoint_cls)

    async def _request_isolated(
        self,
        httpx2_mod: Any,
        req_verify: bool | str,
        proxies: Any,
        cert: Any,
        req_kwargs: dict[str, Any],
    ) -> httpx2.Response:
        proxy_url = _resolve_proxy_url(proxies)
        auth_obj, base_headers = self._build_auth_and_headers()
        transport = self._build_transport(httpx2_mod, req_verify, proxy=proxy_url, cert=cert)
        async with httpx2_mod.AsyncClient(
            auth=auth_obj,
            headers=base_headers,
            follow_redirects=False,
            trust_env=self.config.trust_env,
            transport=transport,
        ) as ephemeral_session:
            response: httpx2.Response = await ephemeral_session.request(**req_kwargs)
            return response

    def _build_async_req_kwargs(
        self,
        httpx2_mod: Any,
        method: str,
        url: str,
        headers: dict[str, Any],
        data: Any,
        params: Mapping[str, Any] | None,
        timeout: Any,
        kwargs: dict[str, Any],
    ) -> tuple[bool | str, dict[str, Any], Any]:
        req_verify, clean_headers, is_json, normalized_data, files = self._normalize_request_parts(
            headers, data, kwargs
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
            req_kwargs["json"] = normalized_data
        elif isinstance(normalized_data, Mapping):
            req_kwargs["data"] = normalized_data
        elif data is not None:
            req_kwargs["content"] = data
        return req_verify, req_kwargs, files

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
        httpx2_mod = _require_httpx2()
        default_verify = SecurityGuard.resolve_tls_verify(self.config.verify)
        proxies = kwargs.pop("proxies", None)
        cert = kwargs.pop("cert", None)
        if kwargs.pop("stream", False):
            msg = "stream=True is not supported on AsyncClient.api_call(); use endpoint.stream()."
            raise ValueError(msg)

        req_verify, req_kwargs, files = self._build_async_req_kwargs(
            httpx2_mod, method, url, headers, data, params, timeout, kwargs
        )
        isolated = req_verify != default_verify or proxies is not None or cert is not None
        stream_reader = getattr(data, "read", None) if "content" in req_kwargs else None
        if callable(stream_reader):
            import asyncio  # ruff: ignore[import-outside-top-level]

            raw_chunk = await asyncio.to_thread(stream_reader)
            req_kwargs["content"] = raw_chunk.encode("utf-8") if isinstance(raw_chunk, str) else raw_chunk
        retry_data = None if callable(stream_reader) else data

        async def _send() -> httpx2.Response:
            if isolated:
                return await self._request_isolated(httpx2_mod, req_verify, proxies, cert, req_kwargs)
            resp: httpx2.Response = await self.session.request(**req_kwargs)
            return resp

        response: httpx2.Response = await run_async_with_retries(
            _send,
            httpx2_mod,
            method=str(method).upper(),
            url=url,
            raw_retries=self.config.max_retries,
            max_retries_limit=Config.MAX_RETRIES_LIMIT,
            allowed_methods=self._RETRY_ALLOWED_METHODS,
            transient_status_codes=self._TRANSIENT_STATUS_CODES,
            max_delay=self._MAX_RETRY_DELAY,
            data=retry_data,
            files=files,
            log=logger,
        )
        self._check_unexpected_redirect(url, response)
        return response

    async def api_call(
        self,
        method: HttpMethod,
        url: str,
        filters: QueryFilters | None = None,
        data: PayloadType = None,
        headers: HeadersMapping | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Execute an authenticated asynchronous API call with SSRF and idempotency guards.

        Returns:
            httpx2.Response: Raw asynchronous HTTP response from Mailjet.
        """
        httpx2_mod = _require_httpx2()
        req_headers, req_timeout, clean_filters, safe_kwargs = self._prepare_api_call(
            method=method,
            url=url,
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
                content=_DRY_RUN_BODY,
                headers={"Content-Type": "application/json"},
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
            raise_timeout_error(logger, method, url, e)
        except (
            httpx2_mod.ConnectError,
            httpx2_mod.NetworkError,
            httpx2_mod.RemoteProtocolError,
            httpx2_mod.ProxyError,
        ) as e:
            raise_connection_error(e)
        except httpx2_mod.HTTPError as e:
            self._handle_api_error(e)
        else:
            self._record_success_telemetry(method, url, response, data, req_headers)
            return response

    async def ping(self, timeout: TimeoutType = None) -> bool:
        """Verify Mailjet API reachability and credentials asynchronously.

        Returns:
            bool: True when the API responds cleanly (< 400); False on API or network error.
        """
        url, filters = self._ping_url(), {"Limit": 1}
        try:
            response = await self.api_call("GET", url, filters=filters, timeout=timeout)
        except ApiError:
            return False
        status = getattr(response, "status_code", 500)
        return isinstance(status, int) and status < 400


# --- Deprecated Wrappers ---
def parse_response(response: requests.Response | httpx2.Response) -> Any:
    """Parse the JSON response or return text if invalid.

    Returns:
        Any: Parsed JSON object or raw response text.
    """
    warnings.warn("parse_response is deprecated.", DeprecationWarning, stacklevel=2)
    try:
        return response.json()
    except ValueError:
        return response.text


def logging_handler(client: Any) -> None:  # ruff: ignore[unused-function-argument]
    """Legacy logging handler (deprecated)."""
    warnings.warn("logging_handler is deprecated.", DeprecationWarning, stacklevel=2)
