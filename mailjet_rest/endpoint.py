"""API Endpoint routing and request building."""

from __future__ import annotations

import warnings
from dataclasses import dataclass
from dataclasses import field
from typing import TYPE_CHECKING
from typing import Any
from urllib.parse import quote

from mailjet_rest.types import _JSON_HEADERS
from mailjet_rest.types import _TEXT_HEADERS
from mailjet_rest.types import HttpMethod
from mailjet_rest.types import PayloadType
from mailjet_rest.types import TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


# Prevent circular import at runtime
if TYPE_CHECKING:
    from collections.abc import Callable
    from collections.abc import Generator

    import requests

    from mailjet_rest.client import Client


# ==========================================
# Routing & Endpoints
# ==========================================


def _route_send(base: str, ver: str, _parts: list[str], _id_val: str, _action: str, _name: str) -> str:
    return f"{base}/{ver}/send"


def _route_csv(base: str, ver: str, parts: list[str], id_val: str, _action: str, name: str) -> str:
    url = f"{base}/{ver}/DATA/{parts[0]}"
    if id_val:  # Only append suffix if an ID was passed
        suffix = "CSVData/text:plain" if name.endswith("_csvdata") else "CSVError/text:csv"
        url += f"{id_val}/{suffix}"
    return url


def _route_data(base: str, ver: str, parts: list[str], id_val: str, action: str, _name: str | None = None) -> str:
    return f"{base}/{ver}/{'/'.join(parts)}{id_val}{action}"


def _route_rest(base: str, ver: str, parts: list[str], id_val: str, action: str, _name: str) -> str:
    if len(parts) > 1:
        # Preserve legacy parity: v1 uses slashes, v3 uses dashes
        sub_action_str = "/".join(parts[1:]) if ver == "v1" else "-".join(parts[1:])
        sub_action = f"/{sub_action_str}"
    else:
        sub_action = ""
    return f"{base}/{ver}/REST/{parts[0]}{id_val}{sub_action}{action}"


ROUTE_STRATEGY: dict[str, Callable[..., str]] = {
    "send": _route_send,
    "csv": _route_csv,
    "data": _route_data,
    "rest": _route_rest,
}


@dataclass(slots=True)
class Endpoint:
    """A class representing a specific Mailjet API endpoint.

    This class provides methods to execute standard HTTP operations (GET, POST, PUT, DELETE)
    dynamically based on the requested resource.
    """

    client: Client
    name: str
    _name_lower: str = field(init=False)
    _action_parts: list[str] = field(init=False)
    _resource_lower: str = field(init=False)

    def __post_init__(self) -> None:
        """Pre-compute routing strings ONCE instead of on every network call."""
        self._name_lower = self.name.lower()
        parts = self.name.split("_")

        # Base resource ignores CamelCase-to-dash conversion (matches legacy behavior)
        self._resource_lower = parts[0].lower()
        self._action_parts = [self._resource_lower]

        # Re-implement camelCase-to-dash conversion natively for sub-actions
        if len(parts) > 1:
            for part in parts[1:]:
                # Convert 'linkClick' to 'link-click' natively
                dashed = "".join("-" + c.lower() if c.isupper() else c for c in part)
                self._action_parts.append(dashed.lstrip("-"))

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

        SecurityGuard.validate_dx_routing(version, self._name_lower, self._resource_lower)

        safe_id = f"/{quote(str(id_val), safe='')}" if id_val is not None else ""
        safe_action = f"/{quote(str(action_id), safe='')}" if action_id is not None else ""

        if self._name_lower == "send":
            strategy = "send"
        elif self._name_lower.endswith(("_csvdata", "_csverror")):
            strategy = "csv"
        elif self._resource_lower == "data":
            strategy = "data"
        else:
            strategy = "rest"

        # Pass self._name_lower into the strategy
        return ROUTE_STRATEGY[strategy](base_url, version, self._action_parts, safe_id, safe_action, self._name_lower)

    def _build_headers(self, custom_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build headers based on the endpoint requirements.

        Args:
            custom_headers (dict[str, str] | None): Custom headers to merge.

        Returns:
            dict[str, str]: The finalized HTTP headers.
        """
        # Select the base immutable mapping proxy
        base_headers = _TEXT_HEADERS if self._name_lower.endswith("_csvdata") else _JSON_HEADERS

        if custom_headers:
            SecurityGuard.validate_crlf_headers(custom_headers)
            return {**base_headers, **custom_headers}

        return dict(base_headers)

    def __call__(
        self,
        method: HttpMethod = "GET",
        filters: dict[str, Any] | None = None,
        data: PayloadType = None,
        headers: dict[str, str] | None = None,
        id: int | str | None = None,  # noqa: A002
        action_id: int | str | None = None,
        timeout: TimeoutType = None,  # noqa: PYI041
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the API call dynamically.

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

        # Delegate cleanly to the Client orchestrator
        return self.client.api_call(
            method=method,
            url=self._build_url(id_val=id, action_id=action_id),
            filters=filters,
            data=data,
            headers=self._build_headers(headers),
            timeout=timeout,
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

    def stream(
        self,
        filters: dict[str, Any] | None = None,
        chunk_size: int = 100,
        method: HttpMethod = "GET",
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """Transparently yields resources, handling pagination automatically.

        Args:
            filters (dict[str, Any] | None): Query parameters.
            chunk_size (int): Number of items to fetch per API request (max 1000).
            method: HttpMethod: only GET allowed.
            **kwargs (Any): Additional arguments.

        Yields:
            dict[str, Any]: Individual resource items from the API.
        """
        if method.upper() != "GET":
            msg = f"stream() is designed for GET requests only, got {method}"
            raise ValueError(msg)
        current_offset = 0
        total = float("inf")
        current_filters = dict(filters) if filters else {}

        while current_offset < total:
            current_filters.update({"Limit": chunk_size, "Offset": current_offset})
            response = self.get(filters=current_filters, **kwargs)
            data = response.json()
            try:
                items = data.get("Data", [])
                if not items:
                    break
                yield from items
                current_offset += chunk_size
            finally:
                response.close()

    def create(
        self,
        data: PayloadType = None,
        id: int | str | None = None,  # noqa: A002
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a POST request to create a new resource.

        Args:
            data (PayloadType): Request payload.
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
        data: PayloadType = None,
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a PUT request to update an existing resource.

        Args:
            id (int | str): The primary resource ID.
            data (PayloadType): Updated payload.
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
