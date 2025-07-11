"""This module provides the main client and helper classes for interacting with the Mailjet API.

The `mailjet_rest.client` module includes the core `Client` class for managing
API requests, configuration, and error handling, as well as utility functions
and classes for building request headers, URLs, and parsing responses.

Classes:
    - Config: Manages configuration settings for the Mailjet API.
    - Endpoint: Represents specific API endpoints and provides methods for
      common HTTP operations like GET, POST, PUT, and DELETE.
    - Client: The main API client for authenticating and making requests.
    - ApiError: Base class for handling API-specific errors, with subclasses
      for more specific error types (e.g., `AuthorizationError`, `TimeoutError`).

Functions:
    - prepare_url: Prepares URLs for API requests.
    - api_call: A helper function that sends HTTP requests to the API and handles
      responses.
    - build_headers: Builds HTTP headers for the requests.
    - build_url: Constructs the full API URL based on endpoint and parameters.
    - parse_response: Parses API responses and handles error conditions.

Exceptions:
    - ApiError: Base exception for API errors, with subclasses to represent
      specific error types, such as `AuthorizationError`, `TimeoutError`,
      `ActionDeniedError`, and `ValidationError`.
"""

from __future__ import annotations

import json
import logging
import re
import sys
from datetime import datetime
from datetime import timezone
from re import Match
from typing import TYPE_CHECKING
from typing import Any

import requests  # type: ignore[import-untyped]
from requests.compat import urljoin  # type: ignore[import-untyped]

from mailjet_rest.utils.version import get_version


if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Mapping

    from requests.models import Response  # type: ignore[import-untyped]


requests.packages.urllib3.disable_warnings()  # type: ignore[attr-defined]


def prepare_url(key: Match[str]) -> str:
    """Replace capital letters in the input string with a dash prefix and converts them to lowercase.

    Parameters:
    key (Match[str]): A match object representing a substring from the input string. The substring should contain a single capital letter.

    Returns:
    str: A string containing a dash followed by the lowercase version of the input capital letter.
    """
    char_elem = key.group(0)
    if char_elem.isupper():
        return "-" + char_elem.lower()
    return ""


class Config:
    """Configuration settings for interacting with the Mailjet API.

    This class stores and manages API configuration details, including the API URL,
    version, and user agent string. It provides methods for initializing these settings
    and generating endpoint-specific URLs and headers as required for API interactions.

    Attributes:
        DEFAULT_API_URL (str): The default base URL for Mailjet API requests.
        API_REF (str): Reference URL for Mailjet's API documentation.
        version (str): API version to use, defaulting to 'v3'.
        user_agent (str): User agent string including the package version for tracking.
    """

    DEFAULT_API_URL: str = "https://api.mailjet.com/"
    API_REF: str = "https://dev.mailjet.com/email-api/v3/"
    version: str = "v3"
    user_agent: str = "mailjet-apiv3-python/v" + get_version()

    def __init__(self, version: str | None = None, api_url: str | None = None) -> None:
        """Initialize a new Config instance with specified or default API settings.

        This initializer sets the API version and base URL. If no version or URL
        is provided, it defaults to the predefined class values.

        Parameters:
        - version (str | None): The API version to use. If None, the default version ('v3') is used.
        - api_url (str | None): The base URL for API requests. If None, the default URL (DEFAULT_API_URL) is used.
        """
        if version is not None:
            self.version = version
        self.api_url = api_url or self.DEFAULT_API_URL

    def __getitem__(self, key: str) -> tuple[str, dict[str, str]]:
        """Retrieve the API endpoint URL and headers for a given key.

        This method builds the URL and headers required for specific API interactions.
        The URL is adjusted based on the API version, and additional headers are
        appended depending on the endpoint type. Specific keys modify content-type
        for endpoints expecting CSV or plain text.

        Parameters:
        - key (str): The name of the API endpoint, which influences URL structure and header configuration.

        Returns:
        - tuple[str, dict[str, str]]: A tuple containing the constructed URL and headers required for the specified endpoint.

        Examples:
            For the "contactslist_csvdata" key, a URL pointing to 'DATA/' and a
            'Content-type' of 'text/plain' is returned.
            For the "batchjob_csverror" key, a URL with 'DATA/' and a 'Content-type'
            of 'text/csv' is returned.
        """
        # Append version to URL.
        # Forward slash is ignored if present in self.version.
        url = urljoin(self.api_url, self.version + "/")
        headers: dict[str, str] = {
            "Content-type": "application/json",
            "User-agent": self.user_agent,
        }
        if key.lower() == "contactslist_csvdata":
            url = urljoin(url, "DATA/")
            headers["Content-type"] = "text/plain"
        elif key.lower() == "batchjob_csverror":
            url = urljoin(url, "DATA/")
            headers["Content-type"] = "text/csv"
        elif key.lower() != "send" and self.version != "v4":
            url = urljoin(url, "REST/")
        url += key.split("_")[0].lower()
        return url, headers


class Endpoint:
    """A class representing a specific Mailjet API endpoint.

    This class provides methods to perform HTTP requests to a given API endpoint,
    including GET, POST, PUT, and DELETE requests. It manages URL construction,
    headers, and authentication for interacting with the endpoint.

    Attributes:
    - _url (str): The base URL of the endpoint.
    - headers (dict[str, str]): The headers to be included in API requests.
    - _auth (tuple[str, str] | None): The authentication credentials.
    - action (str | None): The specific action to be performed on the endpoint.

    Methods:
    - _get: Internal method to perform a GET request.
    - get_many: Performs a GET request to retrieve multiple resources.
    - get: Performs a GET request to retrieve a specific resource.
    - create: Performs a POST request to create a new resource.
    - update: Performs a PUT request to update an existing resource.
    - delete: Performs a DELETE request to delete a resource.
    """

    def __init__(
        self,
        url: str,
        headers: dict[str, str],
        auth: tuple[str, str] | None,
        action: str | None = None,
    ) -> None:
        """Initialize a new Endpoint instance.

        Args:
            url (str): The base URL for the endpoint.
            headers (dict[str, str]): Headers for API requests.
            auth (tuple[str, str] | None): Authentication credentials.
            action (str | None): Action to perform on the endpoint, if any.
        """
        self._url, self.headers, self._auth, self.action = url, headers, auth, action

    def _get(
        self,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        """Perform an internal GET request to the endpoint.

        Constructs the URL with the provided filters and action_id to retrieve
        specific data from the API.

        Parameters:
        - filters (Mapping[str, str | Any] | None): Filters to be applied in the request.
        - action_id (str | None): The specific action ID for the endpoint to be performed.
        - id (str | None): The ID of the specific resource to be retrieved.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call.
        """
        return api_call(
            self._auth,
            "get",
            self._url,
            headers=self.headers,
            action=self.action,
            action_id=action_id,
            filters=filters,
            resource_id=id,
            **kwargs,
        )

    def get_many(
        self,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        """Perform a GET request to retrieve multiple resources.

        Parameters:
        - filters (Mapping[str, str | Any] | None): Filters to be applied in the request.
        - action_id (str | None): The specific action ID to be performed.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call containing multiple resources.
        """
        return self._get(filters=filters, action_id=action_id, **kwargs)

    def get(
        self,
        id: str | None = None,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        **kwargs: Any,
    ) -> Response:
        """Perform a GET request to retrieve a specific resource.

        Parameters:
        - id (str | None): The ID of the specific resource to be retrieved.
        - filters (Mapping[str, str | Any] | None): Filters to be applied in the request.
        - action_id (str | None): The specific action ID to be performed.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call containing the specific resource.
        """
        return self._get(id=id, filters=filters, action_id=action_id, **kwargs)

    def create(
        self,
        data: str | bytes | dict[Any, Any] | None = None,
        filters: Mapping[str, str | Any] | None = None,
        id: str | None = None,
        action_id: str | None = None,
        ensure_ascii: bool = True,
        data_encoding: str = "utf-8",
        **kwargs: Any,
    ) -> Response:
        """Perform a POST request to create a new resource.

        Parameters:
        - data (str | bytes | dict[Any, Any] | None): The data to include in the request body.
        - filters (Mapping[str, str | Any] | None): Filters to be applied in the request.
        - id (str | None): The ID of the specific resource to be created.
        - action_id (str | None): The specific action ID to be performed.
        - ensure_ascii (bool): Whether to ensure ASCII characters in the data.
        - data_encoding (str): The encoding to be used for the data.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call.
        """
        if self.headers.get("Content-type") == "application/json" and data is not None:
            data = json.dumps(
                data,
                ensure_ascii=ensure_ascii,
            )
            if not ensure_ascii:
                data = data.encode(data_encoding)
        return api_call(
            self._auth,
            "post",
            self._url,
            headers=self.headers,
            resource_id=id,
            data=data,  # type: ignore[arg-type]
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def update(
        self,
        id: str | None,
        data: dict | None = None,
        filters: Mapping[str, str | Any] | None = None,
        action_id: str | None = None,
        ensure_ascii: bool = True,
        data_encoding: str = "utf-8",
        **kwargs: Any,
    ) -> Response:
        """Perform a PUT request to update an existing resource.

        Parameters:
        - id (str | None): The ID of the specific resource to be updated.
        - data (dict | None): The data to be sent in the request body.
        - filters (Mapping[str, str | Any] | None): Filters to be applied in the request.
        - action_id (str | None): The specific action ID to be performed.
        - ensure_ascii (bool): Whether to ensure ASCII characters in the data.
        - data_encoding (str): The encoding to be used for the data.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call.
        """
        json_data: str | bytes | None = None
        if self.headers.get("Content-type") == "application/json" and data is not None:
            json_data = json.dumps(data, ensure_ascii=ensure_ascii)
            if not ensure_ascii:
                json_data = json_data.encode(data_encoding)
        return api_call(
            self._auth,
            "put",
            self._url,
            resource_id=id,
            headers=self.headers,
            data=json_data,
            action=self.action,
            action_id=action_id,
            filters=filters,
            **kwargs,
        )

    def delete(self, id: str | None, **kwargs: Any) -> Response:
        """Perform a DELETE request to delete a resource.

        Parameters:
        - id (str | None): The ID of the specific resource to be deleted.
        - **kwargs (Any): Additional keyword arguments to be passed to the API call.

        Returns:
        - Response: The response object from the API call.
        """
        return api_call(
            self._auth,
            "delete",
            self._url,
            action=self.action,
            headers=self.headers,
            resource_id=id,
            **kwargs,
        )


class Client:
    """A client for interacting with the Mailjet API.

    This class manages authentication, configuration, and API endpoint access.
    It initializes with API authentication details and uses dynamic attribute access
    to allow flexible interaction with various Mailjet API endpoints.

    Attributes:
    - auth  (tuple[str, str] | None): A tuple containing the API key and secret for authentication.
    - config (Config): An instance of the Config class, which holds API configuration settings.

    Methods:
    - __init__: Initializes a new Client instance with authentication and configuration settings.
    - __getattr__: Handles dynamic attribute access, allowing for accessing API endpoints as attributes.
    """

    def __init__(self, auth: tuple[str, str] | None = None, **kwargs: Any) -> None:
        """Initialize a new Client instance for API interaction.

        This method sets up API authentication and configuration. The `auth` parameter
        provides a tuple with the API key and secret. Additional keyword arguments can
        specify configuration options like API version and URL.

        Parameters:
        - auth (tuple[str, str] | None): A tuple containing the API key and secret for authentication. If None, authentication is not required.
        - **kwargs (Any): Additional keyword arguments, such as `version` and `api_url`, for configuring the client.

        Example:
            client = Client(auth=("api_key", "api_secret"), version="v3")
        """
        self.auth = auth
        version: str | None = kwargs.get("version")
        api_url: str | None = kwargs.get("api_url")
        self.config = Config(version=version, api_url=api_url)

    def __getattr__(self, name: str) -> Any:
        """Dynamically access API endpoints as attributes.

        This method allows for flexible, attribute-style access to API endpoints.
        It constructs the appropriate endpoint URL and headers based on the attribute
        name, which it parses to identify the resource and optional sub-resources.

        Parameters:
        - name (str): The name of the attribute being accessed, corresponding to the Mailjet API endpoint.


        Returns:
        - Endpoint: An instance of the `Endpoint` class, initialized with the constructed URL, headers, action, and authentication details.
        """
        name_regex: str = re.sub(r"[A-Z]", prepare_url, name)
        split: list[str] = name_regex.split("_")  # noqa: RUF100
        # identify the resource
        fname: str = split[0]
        action: str | None = None
        if len(split) > 1:
            # identify the sub resource (action)
            action = split[1]
            if action == "csvdata":
                action = "csvdata/text:plain"
            if action == "csverror":
                action = "csverror/text:csv"
        url, headers = self.config[name]
        return type(fname, (Endpoint,), {})(
            url=url,
            headers=headers,
            action=action,
            auth=self.auth,
        )


def api_call(
    auth: tuple[str, str] | None,
    method: str,
    url: str,
    headers: dict[str, str],
    data: str | bytes | None = None,
    filters: Mapping[str, str | Any] | None = None,
    resource_id: str | None = None,
    timeout: int = 60,
    debug: bool = False,
    action: str | None = None,
    action_id: str | None = None,
    **kwargs: Any,
) -> Response | Any:
    """Make an API call to a specified URL using the provided method, headers, and other parameters.

    Parameters:
    - auth (tuple[str, str] | None): A tuple containing the API key and secret for authentication.
    - method (str): The HTTP method to be used for the API call (e.g., 'get', 'post', 'put', 'delete').
    - url (str): The URL to which the API call will be made.
    - headers (dict[str, str]): A dictionary containing the headers to be included in the API call.
    - data (str | bytes | None): The data to be sent in the request body.
    - filters (Mapping[str, str | Any] | None): A dictionary containing filters to be applied in the request.
    - resource_id (str | None): The ID of the specific resource to be accessed.
    - timeout (int): The timeout for the API call in seconds.
    - debug (bool): A flag indicating whether debug mode is enabled.
    - action (str | None): The specific action to be performed on the resource.
    - action_id (str | None): The ID of the specific action to be performed.
    - **kwargs (Any): Additional keyword arguments to be passed to the API call.

    Returns:
    - Response | Any: The response object from the API call if the request is successful, or an exception if an error occurs.
    """
    url = build_url(
        url,
        method=method,
        action=action,
        resource_id=resource_id,
        action_id=action_id,
    )
    req_method = getattr(requests, method)

    try:
        filters_str: str | None = None
        if filters:
            filters_str = "&".join(f"{k}={v}" for k, v in filters.items())
        response = req_method(
            url,
            data=data,
            params=filters_str,
            headers=headers,
            auth=auth,
            timeout=timeout,
            verify=True,
            stream=False,
        )

    except requests.exceptions.Timeout:
        raise TimeoutError
    except requests.RequestException as e:
        raise ApiError(e)  # noqa: RUF100, B904
    except Exception:
        raise
    else:
        return response


def build_headers(
    resource: str,
    action: str,
    extra_headers: dict[str, str] | None = None,
) -> dict[str, str]:
    """Build headers based on resource and action.

    Parameters:
    - resource (str): The name of the resource for which headers are being built.
    - action (str): The specific action being performed on the resource.
    - extra_headers (dict[str, str] | None): Additional headers to be included in the request. Defaults to None.

    Returns:
    - dict[str, str]: A dictionary containing the headers to be included in the API request.
    """
    headers: dict[str, str] = {"Content-type": "application/json"}

    if resource.lower() == "contactslist" and action.lower() == "csvdata":
        headers = {"Content-type": "text/plain"}
    elif resource.lower() == "batchjob" and action.lower() == "csverror":
        headers = {"Content-type": "text/csv"}

    if extra_headers:
        headers.update(extra_headers)

    return headers


def build_url(
    url: str,
    method: str | None,
    action: str | None = None,
    resource_id: str | None = None,
    action_id: str | None = None,
) -> str:
    """Construct a URL for making an API request.

    This function takes the base URL, method, action, resource ID, and action ID as parameters
    and constructs a URL by appending the resource ID, action, and action ID to the base URL.

    Parameters:
    url (str): The base URL for the API request.
    method (str | None): The HTTP method for the API request (e.g., 'get', 'post', 'put', 'delete').
    action (str | None): The specific action to be performed on the resource. Defaults to None.
    resource_id (str | None): The ID of the specific resource to be accessed. Defaults to None.
    action_id (str | None): The ID of the specific action to be performed. Defaults to None.

    Returns:
    str: The constructed URL for the API request.
    """
    if resource_id:
        url += f"/{resource_id}"
    if action:
        url += f"/{action}"
        if action_id:
            url += f"/{action_id}"
    return url


def logging_handler(
    to_file: bool = False,
) -> logging.Logger:
    """Create and configure a logger for logging API requests.

    This function creates a logger object and configures it to handle both
    standard output (stdout) and a file if the `to_file` parameter is set to True.
    The logger is set to log at the DEBUG level and uses a custom formatter to
    include the log level and message.

    Parameters:
    to_file (bool): A flag indicating whether to log to a file. If True, logs will be written to a file.
                     Defaults to False.

    Returns:
    logging.Logger: A configured logger object for logging API requests.
    """
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    formatter = logging.Formatter("%(levelname)s | %(message)s")

    if to_file:
        now = datetime.now(tz=timezone.utc)
        date_time = now.strftime("%Y%m%d_%H%M%S")

        log_file = f"{date_time}.log"
        file_handler = logging.FileHandler(log_file)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    stdout_handler = logging.StreamHandler(sys.stdout)
    stdout_handler.setFormatter(formatter)
    logger.addHandler(stdout_handler)

    return logger


def parse_response(
    response: Response,
    log: Callable,
    debug: bool = False,
) -> Any:
    """Parse the response from an API request and return the JSON data.

    Parameters:
    response (Response): The response object from the API request.
    log (Callable): A function or method that logs debug information.
    debug (bool): A flag indicating whether debug mode is enabled. Defaults to False.

    Returns:
    Any: The JSON data from the API response.
    """
    data = response.json()

    if debug:
        lgr = log()
        lgr.debug("REQUEST: %s", response.request.url)
        lgr.debug("REQUEST_HEADERS: %s", response.request.headers)
        lgr.debug("REQUEST_CONTENT: %s", response.request.body)

        lgr.debug("RESPONSE: %s", response.content)
        lgr.debug("RESP_HEADERS: %s", response.headers)
        lgr.debug("RESP_CODE: %s", response.status_code)
        # Clear logger handlers to prevent making log duplications
        logging.getLogger().handlers.clear()

    return data


class ApiError(Exception):
    """Base class for all API-related errors.

    This exception serves as the root for all custom API error types,
    allowing for more specific error handling based on the type of API
    failure encountered.
    """


class AuthorizationError(ApiError):
    """Error raised for authorization failures.

    This error is raised when the API request fails due to invalid
    or missing authentication credentials.
    """


class ActionDeniedError(ApiError):
    """Error raised when an action is denied by the API.

    This exception is triggered when an action is requested but is not
    permitted, likely due to insufficient permissions.
    """


class CriticalApiError(ApiError):
    """Error raised for critical API failures.

    This error represents severe issues with the API or infrastructure
    that prevent requests from completing.
    """


class ApiRateLimitError(ApiError):
    """Error raised when the API rate limit is exceeded.

    This exception is raised when the user has made too many requests
    within a given time frame, as enforced by the API's rate limit policy.
    """


class TimeoutError(ApiError):
    """Error raised when an API request times out.

    This error is raised if an API request does not complete within
    the allowed timeframe, possibly due to network issues or server load.
    """


class DoesNotExistError(ApiError):
    """Error raised when a requested resource does not exist.

    This exception is triggered when a specific resource is requested
    but cannot be found in the API, indicating a potential data mismatch
    or invalid identifier.
    """


class ValidationError(ApiError):
    """Error raised for invalid input data.

    This exception is raised when the input data for an API request
    does not meet validation requirements, such as incorrect data types
    or missing fields.
    """
