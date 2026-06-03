"""API Endpoint routing and request building."""

from __future__ import annotations

import re
import warnings
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _JSON_HEADERS, _TEXT_HEADERS, HttpMethod, PayloadType, TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


# Prevent circular import at runtime
if TYPE_CHECKING:
    from collections.abc import Callable, Generator

    import requests

    from mailjet_rest.client import Client


# ==========================================
# Routing & Endpoints
# ==========================================


def _route_send(base: str, ver: str, _parts: list[str], _id_val: str, _action: str, _name: str) -> str:
    return f"{base}/{ver}/send"


def _route_csv(base: str, ver: str, parts: list[str], id_val: str, _action: str, name: str) -> str:
    # 1. quote() encodes slashes and spaces (CWE-20)
    # 2. replace() explicitly encodes dots to prevent strict ".." evaluation (CWE-22)
    safe_part = quote(parts[0], safe="").replace(".", "%2E")

    url = f"{base}/{ver}/DATA/{safe_part}"
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
        """Constructs the fully qualified API URL.

        Leverages immutable static registry routing mappings with URI template
        safe injection gates to fail-closed against cross-boundary vulnerabilities.

        Args:
            id_val (int | str | None): The resource ID.
            action_id (int | str | None): Additional specific resource action id.

        Returns:
            str: The fully qualified, sanitized secure URL.
        """
        # 1. Registry-First Routing (Express Lane Orchestrator)
        if self.name in ROUTE_MAP:
            route = ROUTE_MAP[self.name]
            base_url = self.client.config.api_url.rstrip("/")
            version = route.version if route.version is not None else self.client.config.version

            # Validate structural DX constraints prior to assembly
            SecurityGuard.validate_dx_routing(version, self._name_lower, self._resource_lower)

            path = route.path

            # Enforce centralized sanitization layer directly on URI template parameters
            if id_val is not None and "{" in path:
                safe_id = SecurityGuard.sanitize_segment(id_val)
                path = re.sub(r"\{[^}]+\}", safe_id, path, count=1)
                id_val = None  # Parameter fully consumed by the template boundary

            if action_id is not None and "{" in path:
                safe_action = SecurityGuard.sanitize_segment(action_id)
                path = re.sub(r"\{[^}]+\}", safe_action, path, count=1)
                action_id = None  # Parameter fully consumed by the template boundary

            # Assemble clean path matrix
            url = f"{base_url}/{version}/{path}"

            # Append any unconsumed trailing parameters safely
            if id_val is not None:
                url += f"/{SecurityGuard.sanitize_segment(id_val)}"
            if action_id is not None:
                url += f"/{SecurityGuard.sanitize_segment(action_id)}"

            return url

        # 2. Existing Fallback (Legacy Support)
        # This keeps  original routing logic running for everything else
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
