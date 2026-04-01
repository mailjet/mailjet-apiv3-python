"""This module provides the main client and helper classes for interacting with the Mailjet API.

The `mailjet_rest.client` module includes the core `Client` class for managing
API requests, configuration, and error handling, as well as utility functions
and classes for building URLs and managing endpoints.

Classes:
    - Config: Manages configuration settings for the Mailjet API.
    - Endpoint: Represents specific API endpoints and provides methods for HTTP operations.
    - Client: The main API client for authenticating and making requests.
    - ApiError: Base class for handling network-level API errors.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from typing import Any

import requests  # pyright: ignore[reportMissingModuleSource]
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException
from requests.exceptions import Timeout as RequestsTimeout

from mailjet_rest._version import __version__


__all__ = [
    "ApiError",
    "Client",
    "Config",
    "CriticalApiError",
    "Endpoint",
    "TimeoutError",
]

logger = logging.getLogger(__name__)


def prepare_url(match: Any) -> str:
    """Replace capital letters in the input string with a dash prefix and converts them to lowercase.

    Args:
        match (Any): A regex match object representing a substring from the input string containing a capital letter.

    Returns:
        str: A string containing a dash followed by the lowercase version of the input capital letter.
    """
    return f"_{match.group(0).lower()}"


class ApiError(Exception):
    """Base class for all API-related network errors.

    This exception serves as the root for custom API error types,
    handling situations where the physical network request fails.
    """


class CriticalApiError(ApiError):
    """Error raised for critical API connection failures.

    This error represents severe network issues (like DNS resolution failure
    or connection refused) that prevent requests from reaching the server.
    """


class TimeoutError(ApiError):
    """Error raised when an API request times out.

    This error is raised if an API request does not complete within
    the allowed timeframe, possibly due to network latency or server load.
    """


@dataclass
class Config:
    """Configuration settings for interacting with the Mailjet API.

    This class stores and manages API configuration details, including the API URL,
    version, and user agent string.

    Attributes:
        version (str): API version to use, defaulting to 'v3'.
        api_url (str): The base URL for Mailjet API requests.
        user_agent (str): User agent string including the package version for tracking.
        timeout (int): Default timeout in seconds for API requests.
    """

    version: str = "v3"
    api_url: str = "https://api.mailjet.com/"
    user_agent: str = f"mailjet-apiv3-python/v{__version__}"
    timeout: int = 15

    def __getitem__(self, key: str) -> tuple[str, dict[str, str]]:
        """Retrieve the API endpoint URL and headers for a given key.

        This method builds the URL and headers required for specific API interactions.
        It is maintained primarily for backward compatibility.

        Args:
            key (str): The name of the API endpoint.

        Returns:
            tuple[str, dict[str, str]]: A tuple containing the constructed URL and headers.
        """
        action = key.split("_")[0]
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

    This class provides methods to perform HTTP requests to a given API endpoint,
    including GET, POST, PUT, and DELETE requests. It manages dynamic URL construction
    and headers based on the requested resource.

    Attributes:
        client (Client): The parent Mailjet API client instance.
        name (str): The specific endpoint or action name.
    """

    def __init__(self, client: Client, name: str) -> None:
        """Initialize a new Endpoint instance.

        Args:
            client (Client): The Mailjet Client session manager.
            name (str): The dynamic name of the endpoint being accessed.
        """
        self.client = client
        self.name = name

    def _build_url(self, id: int | str | None = None) -> str:
        """Construct the URL for the specific API request.

        Args:
            id (int | str | None): The ID of the specific resource, if applicable.

        Returns:
            str: The fully qualified URL for the API endpoint.
        """
        base_url = self.client.config.api_url.rstrip("/")
        version = self.client.config.version
        name_lower = self.name.lower()

        if name_lower == "send":
            return f"{base_url}/{version}/send"

        action_parts = self.name.split("_")
        resource = action_parts[0]

        if name_lower.endswith(("_csvdata", "_csverror")):
            url = f"{base_url}/{version}/DATA/{resource}"
            if id is not None:
                suffix = "CSVData/text:plain" if name_lower.endswith("_csvdata") else "CSVError/text:csv"
                url += f"/{id}/{suffix}"
            return url

        if resource.lower() == "data":
            # Content API Data Endpoints (e.g. data_images -> /v1/data/images)
            action_path = "/".join(action_parts)
            url = f"{base_url}/{version}/{action_path}"
        else:
            # Standard REST API (v1 and v3)
            url = f"{base_url}/{version}/REST/{resource}"

        if id is not None:
            url += f"/{id}"

        if len(action_parts) > 1 and resource.lower() != "data":
            sub_action = "/".join(action_parts[1:]) if version == "v1" else "-".join(action_parts[1:])
            url += f"/{sub_action}"

        return url

    def _build_headers(self, custom_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build headers based on the endpoint requirements.

        Args:
            custom_headers (dict[str, str] | None): Additional headers to include.

        Returns:
            dict[str, str]: A dictionary containing the standard and custom headers.
        """
        headers = {}
        if self.name.lower().endswith("_csvdata"):
            headers["Content-Type"] = "text/plain"
        else:
            headers["Content-Type"] = "application/json"

        if custom_headers:
            headers.update(custom_headers)
        return headers

    def __call__(
        self,
        method: str = "GET",
        filters: dict[str, Any] | None = None,
        data: dict[str, Any] | list[Any] | str | None = None,
        headers: dict[str, str] | None = None,
        id: int | str | None = None,
        action_id: int | str | None = None,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the API call directly.

        Args:
            method (str): The HTTP method to use (e.g., 'GET', 'POST').
            filters (dict[str, Any] | None): Query parameters to include in the request.
            data (dict[str, Any] | list[Any] | str | None): The payload to send in the request body.
            headers (dict[str, str] | None): Custom HTTP headers.
            id (int | str | None): The ID of the resource to access.
            action_id (int | str | None): Legacy parameter, acts as an alias for id.
            timeout (int | None): Custom timeout for this specific request.
            **kwargs (Any): Additional arguments passed to the underlying requests Session.

        Returns:
            requests.Response: The HTTP response from the Mailjet API.
        """
        if id is None and action_id is not None:
            id = action_id

        if filters is None and "filter" in kwargs:
            filters = kwargs.pop("filter")
        elif "filter" in kwargs:
            kwargs.pop("filter")

        return self.client.api_call(
            method=method,
            url=self._build_url(id=id),
            filters=filters,
            data=data,
            headers=self._build_headers(headers),
            timeout=timeout or self.client.config.timeout,
            **kwargs,
        )

    def get(
        self, id: int | str | None = None, filters: dict[str, Any] | None = None, **kwargs: Any
    ) -> requests.Response:
        """Perform a GET request to retrieve one or multiple resources.

        Args:
            id (int | str | None): The ID of the specific resource to retrieve.
            filters (dict[str, Any] | None): Query parameters for filtering the results.
            **kwargs (Any): Additional arguments for the API call.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="GET", id=id, filters=filters, **kwargs)

    def create(
        self,
        data: dict[str, Any] | list[Any] | str | None = None,
        id: int | str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a POST request to create a new resource.

        Args:
            data (dict[str, Any] | list[Any] | str | None): The payload data to create the resource.
            id (int | str | None): The ID of the resource, if creating a sub-resource.
            **kwargs (Any): Additional arguments for the API call.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="POST", data=data, id=id, **kwargs)

    def update(
        self, id: int | str, data: dict[str, Any] | list[Any] | str | None = None, **kwargs: Any
    ) -> requests.Response:
        """Perform a PUT request to update an existing resource.

        According to the Mailjet API documentation, all PUT requests behave like
        PATCH requests, affecting only the specified properties.

        Args:
            id (int | str): The exact ID of the resource to update.
            data (dict[str, Any] | list[Any] | str | None): The updated payload data.
            **kwargs (Any): Additional arguments for the API call.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="PUT", id=id, data=data, **kwargs)

    def delete(self, id: int | str, **kwargs: Any) -> requests.Response:
        """Perform a DELETE request to remove a resource.

        Args:
            id (int | str): The exact ID of the resource to delete.
            **kwargs (Any): Additional arguments for the API call.

        Returns:
            requests.Response: The HTTP response from the API.
        """
        return self(method="DELETE", id=id, **kwargs)


class Client:
    """A client for interacting with the Mailjet API.

    This class manages authentication, configuration, and API endpoint access.
    It initializes with API authentication details and uses dynamic attribute access
    to allow flexible interaction with various Mailjet API endpoints.

    Attributes:
        auth (tuple[str, str] | str | None): A tuple containing the API key and secret, or a Bearer token string.
        config (Config): Configuration settings for the API client.
        session (requests.Session): A persistent HTTP session for optimized connection pooling.
    """

    def __init__(
        self,
        auth: tuple[str, str] | str | None = None,
        config: Config | None = None,
        **kwargs: Any,
    ) -> None:
        """Initialize a new Client instance for API interaction.

        Args:
            auth (tuple[str, str] | str | None): A tuple of (API_KEY, API_SECRET) for Basic Auth (Email API), or a single string TOKEN for Bearer Auth (Content API v1).
            config (Config | None): An explicit Config object.
            **kwargs (Any): Additional keyword arguments passed to the Config constructor if no config is provided.

        Raises:
            ValueError: If the provided authentication token or tuple is malformed or invalid.
            TypeError: If the `auth` argument is not of an expected type (tuple, str, or None).
        """
        self.auth = auth
        self.config = config or Config(**kwargs)

        self.session = requests.Session()

        # Bearer Auth is required for the v1 Content API endpoints (Tokens, Templates, Images)
        if self.auth is not None:
            if isinstance(self.auth, tuple):
                if len(self.auth) != 2:
                    msg = "Basic auth tuple must contain exactly two elements: (API_KEY, API_SECRET)."  # type: ignore[unreachable]
                    raise ValueError(msg)
                self.session.auth = self.auth
            elif isinstance(self.auth, str):
                clean_token = self.auth.strip()
                if not clean_token:
                    msg = "Bearer token cannot be an empty string."
                    raise ValueError(msg)
                if "\n" in clean_token or "\r" in clean_token:
                    msg = "Bearer token contains invalid characters (Header Injection risk)."
                    raise ValueError(msg)
                self.session.headers.update({"Authorization": f"Bearer {clean_token}"})
            else:
                msg = f"Invalid auth type: expected tuple, str, or None, got {type(self.auth).__name__}"  # type: ignore[unreachable]
                raise TypeError(msg)

        self.session.headers.update({"User-Agent": self.config.user_agent})

    def __getattr__(self, name: str) -> Endpoint:
        """Dynamically access API endpoints as attributes.

        Args:
            name (str): The name of the attribute being accessed (e.g., 'contact_managecontactslists', 'statcounters').

        Returns:
            Endpoint: An initialized Endpoint instance for the requested resource.
        """
        return Endpoint(self, name)

    def api_call(
        self,
        method: str,
        url: str,
        filters: dict[str, Any] | None = None,
        data: dict[str, Any] | list[Any] | str | None = None,
        headers: dict[str, str] | None = None,
        timeout: int | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform the actual network request using the persistent session.

        This method catches specific network-level exceptions raised by the
        underlying HTTP client and re-raises them as custom API errors to
        decouple the SDK from external library implementations.

        Args:
            method (str): The HTTP method to use.
            url (str): The fully constructed URL.
            filters (dict[str, Any] | None): Query parameters.
            data (dict[str, Any] | list[Any] | str | None): The request body payload.
            headers (dict[str, str] | None): HTTP headers.
            timeout (int | None): Request timeout in seconds.
            **kwargs (Any): Additional arguments to pass to `requests.request`.

        Returns:
            requests.Response: The response object from the HTTP request.

        Raises:
            TimeoutError: If the API request times out.
            CriticalApiError: If there is a connection failure to the API.
            ApiError: For other unhandled underlying request exceptions.
        """
        payload = data
        if isinstance(data, (dict, list)):
            payload = json.dumps(data)

        if timeout is None:
            timeout = self.config.timeout

        logger.debug("Sending Request: %s %s", method.upper(), url)

        try:
            response = self.session.request(
                method=method,
                url=url,
                params=filters,
                data=payload,
                headers=headers,
                timeout=timeout,
                **kwargs,
            )
        except RequestsTimeout as error:
            logger.exception("Timeout Error: %s %s", method.upper(), url)
            msg = f"Request to Mailjet API timed out: {error}"
            raise TimeoutError(msg) from error
        except RequestsConnectionError as error:
            logger.critical("Connection Error: %s | URL: %s", error, url)
            msg = f"Connection to Mailjet API failed: {error}"
            raise CriticalApiError(msg) from error
        except RequestException as error:
            logger.critical("Request Exception: %s | URL: %s", error, url)
            msg = f"An unexpected Mailjet API network error occurred: {error}"
            raise ApiError(msg) from error

        try:
            is_error = response.status_code >= 400
        except TypeError:
            is_error = False

        if is_error:
            logger.error(
                "API Error %s | %s %s | Response: %s",
                response.status_code,
                method.upper(),
                url,
                getattr(response, "text", ""),
            )
        else:
            logger.debug(
                "API Success %s | %s %s",
                getattr(response, "status_code", 200),
                method.upper(),
                url,
            )

        return response
