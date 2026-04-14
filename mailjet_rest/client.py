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
from dataclasses import dataclass
from typing import TYPE_CHECKING
from typing import Any
from typing import ClassVar
from typing import Literal
from typing import cast
from urllib.parse import quote

import requests  # pyright: ignore[reportMissingModuleSource]
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException
from requests.exceptions import Timeout as RequestsTimeout
from urllib3.util.retry import Retry

from mailjet_rest._version import __version__
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from types import TracebackType


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


def prepare_url(match: Any) -> str:
    """Replace capital letters in the input string with a dash prefix and convert to lowercase.

    Args:
        match (Any): A regex match object containing a capital letter.

    Returns:
        str: A formatted URL string fragment (e.g., '_m').
    """
    return f"_{match.group(0).lower()}"


# --- Exceptions ---


class ApiError(Exception):
    """Base class for all API-related network errors."""


class CriticalApiError(ApiError):
    """Error raised for critical API connection failures."""


class TimeoutError(ApiError):  # noqa: A001
    """Error raised when an API request times out."""


# --- Deprecated Legacy Exceptions ---


class AuthorizationError(ApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 401."""


class ActionDeniedError(ApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 403."""


class DoesNotExistError(ApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 404."""


class ValidationError(ApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 400."""


class ApiRateLimitError(ApiError):
    """Deprecated: The SDK natively returns the requests.Response object for 429."""


# --- Deprecated Utilities ---


def parse_response(response: requests.Response, debug: bool = False) -> dict[str, Any] | str:  # noqa: ARG001
    """Deprecated: Extract JSON or text from response.

    Args:
        response (requests.Response): The HTTP response.
        debug (bool): Deprecated debug flag.

    Returns:
        dict[str, Any] | str: The parsed JSON dictionary or raw text string.
    """
    msg = (
        "parse_response is deprecated and will be removed in future releases. "
        "Please use response.json() or response.text directly on the requests.Response object."
    )
    warnings.warn(msg, DeprecationWarning, stacklevel=2)
    try:
        return response.json()
    except ValueError:
        return response.text


def logging_handler(response: requests.Response) -> None:  # noqa: ARG001
    """Deprecated: Custom logging handler.

    Args:
        response (requests.Response): The HTTP response.
    """
    msg = (
        "logging_handler is deprecated and will be removed in future releases. "
        "Logging is now integrated cleanly and automatically via Python's standard `logging` library."
    )
    warnings.warn(msg, DeprecationWarning, stacklevel=2)


# --- Core Classes ---


@dataclass
class Config:
    """Configuration settings for interacting with the Mailjet API.

    Attributes:
        ALLOWED_ROOT_DOMAIN (ClassVar[str]): The permitted root domain to prevent SSRF.
        version (str): The API version to use (e.g., 'v3', 'v3.1', 'v1').
        api_url (str): The base URL for the Mailjet API.
        user_agent (str): The User-Agent string sent with API requests.
        timeout (int | float | tuple[float, float] | None): Request timeout in seconds.
    """

    ALLOWED_ROOT_DOMAIN: ClassVar[str] = "mailjet.com"

    version: str = "v3"
    api_url: str = "https://api.mailjet.com/"
    user_agent: str = f"mailjet-apiv3-python/v{__version__}"
    timeout: int | float | tuple[float, float] | None = 60

    def __post_init__(self) -> None:
        """Validate configuration for secure transport and resource limits (OWASP Input Validation).

        Raises:
            ValueError: If the URL scheme is insecure or timeout bounds are violated.
        """
        SecurityGuard.validate_config_url(self.api_url, allowed_root_domain=self.ALLOWED_ROOT_DOMAIN)
        if not self.api_url.endswith("/"):
            self.api_url += "/"

        def _validate_timeout(t: float) -> None:
            if t <= 0 or t > 300:
                err_msg = f"Timeout values must be strictly between 1 and 300 seconds, got {t}."
                raise ValueError(err_msg)

        if self.timeout is not None:
            if isinstance(self.timeout, tuple):
                # type: ignore[unreachable]
                if len(self.timeout) != 2:
                    msg = f"Timeout tuple must contain exactly two elements, got {self.timeout}."
                    raise ValueError(msg)
                for t_val in self.timeout:
                    _validate_timeout(t_val)
            else:
                _validate_timeout(cast("float", self.timeout))

    def __getitem__(self, key: str) -> tuple[str, dict[str, str]]:
        """Retrieve the base API endpoint URL and default headers for a given key.

        Args:
            key (str): The raw endpoint key name.

        Returns:
            tuple[str, dict[str, str]]: A tuple containing the base URL and the headers dictionary.
        """
        action = key.split("_", maxsplit=1)[0]
        name_lower = key.lower()

        if name_lower == "send":
            url = f"{self.api_url}{self.version}/send"
        elif name_lower.endswith(("_csvdata", "_csverror")):
            url = f"{self.api_url}{self.version}/DATA/{action}"
        elif key.lower().startswith("data_"):
            action_path = key.replace("_", "/")
            url = f"{self.api_url}{self.version}/{action_path}"
        else:
            url = f"{self.api_url}{self.version}/REST/{action}"

        headers = {"Content-type": "application/json"}
        if name_lower.endswith("_csvdata"):
            headers["Content-Type"] = "text/plain"

        return url, headers


class Endpoint:
    """A class representing a specific Mailjet API endpoint.

    This class provides methods to execute standard HTTP operations (GET, POST, PUT, DELETE)
    dynamically based on the requested resource.
    """

    def __init__(self, client: Client, name: str) -> None:
        """Initialize a new Endpoint instance.

        Args:
            client (Client): The active API client managing the session.
            name (str): The resource name (e.g., 'contact', 'send', 'contactslist_csvdata').
        """
        self.client = client
        self.name = name

    @staticmethod
    def _build_csv_url(base_url: str, version: str, resource: str, name_lower: str, id_val: int | str | None) -> str:
        """Construct the URL for CSV data endpoints.

        Args:
            base_url (str): The base API URL.
            version (str): The API version.
            resource (str): The base resource name.
            name_lower (str): The lowercase endpoint name.
            id_val (int | str | None): The primary resource ID.

        Returns:
            str: The fully constructed CSV endpoint URL.
        """
        url = f"{base_url}/{version}/DATA/{resource}"
        if id_val is not None:
            safe_id = quote(str(id_val), safe="")
            suffix = "CSVData/text:plain" if name_lower.endswith("_csvdata") else "CSVError/text:csv"
            url += f"/{safe_id}/{suffix}"
        return url

    def _build_url(self, id_val: int | str | None = None, action_id: int | str | None = None) -> str:
        """Construct the URL for the specific API request.

        Args:
            id_val (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.

        Returns:
            str: The fully qualified URL.
        """
        base_url = self.client.config.api_url.rstrip("/")
        version = self.client.config.version
        name_lower = self.name.lower()

        action_parts = self.name.split("_")
        resource = action_parts[0]
        resource_lower = resource.lower()

        SecurityGuard.validate_dx_routing(version, name_lower, resource_lower)

        if name_lower == "send":
            return f"{base_url}/{version}/send"

        if name_lower.endswith(("_csvdata", "_csverror")):
            return self._build_csv_url(base_url, version, resource, name_lower, id_val)

        if resource_lower == "data":
            action_path = "/".join(action_parts)
            url = f"{base_url}/{version}/{action_path}"
        else:
            url = f"{base_url}/{version}/REST/{resource}"

        if id_val is not None:
            safe_id = quote(str(id_val), safe="")
            url += f"/{safe_id}"

        if len(action_parts) > 1 and resource_lower != "data":
            sub_action = "/".join(action_parts[1:]) if version == "v1" else "-".join(action_parts[1:])
            url += f"/{sub_action}"

        if action_id is not None:
            safe_action_id = quote(str(action_id), safe="")
            url += f"/{safe_action_id}"

        return url

    def _build_headers(self, custom_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build headers based on the endpoint requirements.

        Args:
            custom_headers (dict[str, str] | None): Custom headers to merge.

        Returns:
            dict[str, str]: The finalized HTTP headers.
        """
        headers = {}
        if self.name.lower().endswith("_csvdata"):
            headers["Content-Type"] = "text/plain"
        else:
            headers["Content-Type"] = "application/json"

        if custom_headers:
            SecurityGuard.validate_crlf_headers(custom_headers)
            headers.update(custom_headers)
        return headers

    def __call__(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"] = "GET",
        filters: dict[str, Any] | None = None,
        data: dict[str, Any] | list[Any] | str | None = None,
        headers: dict[str, str] | None = None,
        id: int | str | None = None,  # noqa: A002
        action_id: int | str | None = None,
        timeout: int | float | tuple[float, float] | None = None,  # noqa: PYI041
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the API call directly.

        Args:
            method (Literal["GET", "POST", "PUT", "DELETE"], optional): The HTTP method. Defaults to "GET".
            filters (dict[str, Any] | None, optional): Query parameters to append to the URL.
            data (dict[str, Any] | list[Any] | str | None, optional): The payload for the request body.
            headers (dict[str, str] | None, optional): Additional HTTP headers to send.
            id (int | str | None, optional): The primary resource ID.
            action_id (int | str | None, optional): The secondary ID or action string for nested resources.
            timeout (int | float | tuple[float, float] | None, optional): Custom timeout for this request.
            ensure_ascii (bool | None, optional): Deprecated. Ensure ASCII serialization.
            data_encoding (str | None, optional): Deprecated. Target encoding string for the payload.
            **kwargs (Any): Additional parameters passed to `requests.Session.request`.

        Returns:
            requests.Response: The HTTP response from the Mailjet API.
        """
        if id is None and action_id is not None:
            id = action_id  # noqa: A001
            action_id = None

        if filters is None and "filter" in kwargs:
            filters = kwargs.pop("filter")
        elif "filter" in kwargs:
            kwargs.pop("filter")

        return self.client.api_call(
            method=method,
            url=self._build_url(id_val=id, action_id=action_id),
            filters=filters,
            data=data,
            headers=self._build_headers(headers),
            timeout=timeout or self.client.config.timeout,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def get(
        self,
        id: int | str | None = None,  # noqa: A002
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a GET request to retrieve resources.

        Args:
            id (int | str | None): The primary resource ID.
            filters (dict[str, Any] | None): Query parameters.
            action_id (int | str | None): The sub-action ID.
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="GET", id=id, filters=filters, action_id=action_id, **kwargs)

    def create(
        self,
        data: dict[str, Any] | list[Any] | str | None = None,
        id: int | str | None = None,  # noqa: A002
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a POST request to create a new resource.

        Args:
            data (dict[str, Any] | list[Any] | str | None): Request payload.
            id (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.
            ensure_ascii (bool | None): Ensure ASCII serialization (Deprecated).
            data_encoding (str | None): Data encoding string (Deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        if ensure_ascii is not None or data_encoding is not None:
            msg = (
                "'ensure_ascii' and 'data_encoding' are deprecated and will be removed in future releases. "
                "The underlying requests library handles serialization natively."
            )
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
        return self(
            method="POST",
            data=data,
            id=id,
            action_id=action_id,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def update(
        self,
        id: int | str,  # noqa: A002
        data: dict[str, Any] | list[Any] | str | None = None,
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a PUT request to update an existing resource.

        Args:
            id (int | str): The primary resource ID.
            data (dict[str, Any] | list[Any] | str | None): Updated payload.
            action_id (int | str | None): The sub-action ID.
            ensure_ascii (bool | None): Ensure ASCII serialization (Deprecated).
            data_encoding (str | None): Data encoding string (Deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        if ensure_ascii is not None or data_encoding is not None:
            msg = (
                "'ensure_ascii' and 'data_encoding' are deprecated and will be removed in future releases. "
                "The underlying requests library handles serialization natively."
            )
            warnings.warn(msg, DeprecationWarning, stacklevel=2)
        return self(
            method="PUT",
            id=id,
            data=data,
            action_id=action_id,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def delete(self, id: int | str, action_id: int | str | None = None, **kwargs: Any) -> requests.Response:  # noqa: A002
        """Perform a DELETE request to remove a resource.

        Args:
            id (int | str): The primary resource ID.
            action_id (int | str | None): The sub-action ID.
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="DELETE", id=id, action_id=action_id, **kwargs)


class Client:
    """The primary client for interacting with the Mailjet API.

    Handles authentication, session management, configuration, and dynamic
    endpoint resolution via magic methods (`__getattr__`).

    Examples:
        >>> client = Client(auth=(API_KEY, API_SECRET), version='v3.1')
        >>> response = client.send.create(data=payload)
    """

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

        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            allowed_methods=["GET", "OPTIONS"],
        )
        adapter = HTTPAdapter(max_retries=retry_strategy)
        self.session.mount("https://", adapter)

        if auth is not None:
            if isinstance(auth, tuple):
                if len(auth) != 2:  # type: ignore[unreachable]
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
                raise TypeError(msg)  # type: ignore[unreachable]

        self.session.headers.update({"User-Agent": self.config.user_agent})

    def close(self) -> None:
        """Close the underlying requests.Session and purge memory (CWE-316)."""
        if self.session:
            self.session.auth = None
            self.session.headers.clear()
            self.session.close()

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
        SecurityGuard.validate_attribute_access(self.__class__.__name__, name)
        return Endpoint(self, name)

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
    def _extract_telemetry(data: Any, headers: dict[str, str] | None) -> str:
        """Extract tracing identifiers for safe logging.

        Args:
            data (Any): The request payload.
            headers (dict[str, str] | None): Request headers.

        Returns:
            str: A formatted telemetry trace suffix.
        """
        trace_ctx = []
        with suppress(Exception):
            if isinstance(data, dict):
                messages = data.get("Messages", [{}])
                msg = messages[0] if isinstance(messages, list) and messages else {}
                if cid := msg.get("CustomID"):
                    trace_ctx.append(f"CustomID={SecurityGuard.sanitize_log_trace(cid)}")
                if tid := msg.get("TemplateID"):
                    trace_ctx.append(f"TemplateID={SecurityGuard.sanitize_log_trace(tid)}")
                if cid_raw := data.get("X-MJ-CustomID"):
                    trace_ctx.append(f"CustomID={SecurityGuard.sanitize_log_trace(cid_raw)}")
                if camp := data.get("X-Mailjet-Campaign"):
                    trace_ctx.append(f"Campaign={SecurityGuard.sanitize_log_trace(camp)}")

            if headers:
                for key, val in headers.items():
                    k_low = key.lower()
                    if k_low == "x-mj-customid":
                        trace_ctx.append(f"CustomID={SecurityGuard.sanitize_log_trace(val)}")
                    elif k_low == "x-mailjet-campaign":
                        trace_ctx.append(f"Campaign={SecurityGuard.sanitize_log_trace(val)}")

        return f" | Trace: [{' '.join(trace_ctx)}]" if trace_ctx else ""

    def api_call(
        self,
        method: Literal["GET", "POST", "PUT", "DELETE"],
        url: str,
        filters: dict[str, Any] | None = None,
        data: dict[str, Any] | list[Any] | str | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | float | tuple[float, float] | None = None,  # noqa: PYI041
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform the actual network request using the persistent HTTP session.

        This method acts as the core orchestrator, handling telemetry extraction,
        payload serialization, security guardrails, and centralized logging.

        Args:
            method (Literal["GET", "POST", "PUT", "DELETE"]): The HTTP method.
            url (str): The fully constructed API URL.
            filters (dict[str, Any] | None, optional): Query parameters.
            data (dict[str, Any] | list[Any] | str | None, optional): Request payload.
            headers (dict[str, str] | None, optional): Custom HTTP headers.
            timeout (int | float | tuple[float, float] | None, optional): Request timeout.
            ensure_ascii (bool | None, optional): Deprecated. Ensure ASCII encoding.
            data_encoding (str | None, optional): Deprecated. Data encoding string.
            **kwargs (Any): Additional arguments passed to `requests.Session.request`.

        Returns:
            requests.Response: The HTTP response from the Mailjet API.

        Raises:
            TimeoutError: If the API request times out.
            CriticalApiError: If a connection failure occurs.
            ApiError: For other unhandled network exceptions.
        """
        request_data = self._prepare_payload(data, ensure_ascii, data_encoding)
        timeout_val = timeout if timeout is not None else self.config.timeout

        trace_str = self._extract_telemetry(data, headers)
        SecurityGuard.check_request_security(kwargs)
        kwargs.setdefault("allow_redirects", False)

        logger.debug("Sending Request: %s %s%s", method, url, trace_str)

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=filters,
                data=request_data,
                headers=headers,
                timeout=timeout_val,
                **kwargs,
            )
        except RequestsTimeout as error:
            logger.exception("Timeout Error: %s %s%s", method, url, trace_str)
            msg = f"Request to Mailjet API timed out: {error}"
            raise TimeoutError(msg) from error
        except RequestsConnectionError as error:
            logger.critical("Connection Error: %s | URL: %s%s", error, url, trace_str)
            msg = f"Connection to Mailjet API failed: {error}"
            raise CriticalApiError(msg) from error
        except RequestException as error:
            logger.critical("Request Exception: %s | URL: %s%s", error, url, trace_str)
            msg = f"An unexpected Mailjet API network error occurred: {error}"
            raise ApiError(msg) from error

        self._log_response(response, method, url, trace_str)
        return response
