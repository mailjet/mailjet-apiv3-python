"""API Endpoint routing and request building."""

from __future__ import annotations

import json
import warnings
from typing import TYPE_CHECKING, Any

from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.types import _JSON_HEADERS, _TEXT_HEADERS, HttpMethod, PayloadType, TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from collections.abc import Generator

    import requests

    from mailjet_rest.client import Client


class Endpoint:
    """Represents a specific Mailjet REST resource path.

    Dynamically binds to the HTTP client and coordinates URL generation,
    handling API resource mappings via the strict ROUTE_MAP.
    """

    __slots__ = ("_action_parts", "_name_lower", "_resource_lower", "client", "name")

    def __init__(self, client: Client, name: str) -> None:
        """Initialize the endpoint handler with the parent client and route name."""
        self.client = client
        self.name = name
        self._name_lower = name.lower()
        self._action_parts = self._name_lower.split("_")
        self._resource_lower = self._action_parts[0]

    def _resolve_registry_route(
        self, base_url: str, version: str, id_val: int | str | None, action_id: int | str | None
    ) -> tuple[str, int | str | None, int | str | None]:
        """Resolves URL using the static ROUTE_MAP registry.

        Args:
            base_url (str): The base API URL.
            version (str): The API version string.
            id_val (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.

        Returns:
            tuple[str, int | str | None, int | str | None]: A tuple containing:
                - The resolved base URL string.
                - The remaining, unconsumed 'id_val'.
                - The remaining, unconsumed 'action_id'.
        """
        route = ROUTE_MAP[self.name]
        if route.version is not None:
            version = route.version

        path = route.path
        format_kwargs = {}

        # Interpolate URI variables using safe encoding (CWE-22)
        if "{id}" in path:  # ruff: ignore[missing-f-string-syntax]
            if id_val is None:
                msg = f"Endpoint '{self.name}' requires an 'id' parameter."
                raise ValueError(msg)
            format_kwargs["id"] = SecurityGuard.sanitize_segment(id_val)
            id_val = None

        if "{action_id}" in path:  # ruff: ignore[missing-f-string-syntax] # Fixed the f-string evaluation bug here
            if action_id is None:
                msg = f"Endpoint '{self.name}' requires an 'action_id' parameter."
                raise ValueError(msg)
            format_kwargs["action_id"] = SecurityGuard.sanitize_segment(action_id)
            action_id = None

        if format_kwargs:
            path = path.format(**format_kwargs)

        return f"{base_url}/{version}/{path}", id_val, action_id

    def _resolve_dynamic_route(
        self, base_url: str, version: str, id_val: int | str | None, action_id: int | str | None
    ) -> tuple[str, int | str | None, int | str | None]:
        """Resolves URL using legacy dynamic getattr fallback logic.

        Args:
            base_url (str): The base API URL.
            version (str): The API version string.
            id_val (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.

        Returns:
            tuple[str, int | str | None, int | str | None]: A tuple containing:
                - The resolved base URL string.
                - The remaining, unconsumed 'id_val'.
                - The remaining, unconsumed 'action_id'.
        """
        if self._name_lower == "send":
            url = f"{base_url}/{version}/send"
        elif self._name_lower.endswith(("_csvdata", "_csverror")):
            safe_part = SecurityGuard.sanitize_segment(self._action_parts[0])
            url = f"{base_url}/{version}/DATA/{safe_part}"
            if id_val is not None:
                suffix = "CSVData/text:plain" if self._name_lower.endswith("_csvdata") else "CSVError/text:csv"
                url += f"/{SecurityGuard.sanitize_segment(id_val)}/{suffix}"
                id_val = None

            # Explicitly sanitize action_id so it doesn't bypass _build_url checks
            if action_id is not None:
                action_id = SecurityGuard.sanitize_segment(action_id)

        elif self._name_lower.startswith("data_"):
            safe_path = "/".join(SecurityGuard.sanitize_segment(p) for p in self._action_parts[1:])
            url = f"{base_url}/{version}/data/{safe_path}"

            if action_id is not None:
                action_id = SecurityGuard.sanitize_segment(action_id)

        else:
            url = f"{base_url}/{version}/REST/{self._resource_lower}"
            if len(self._action_parts) > 1:
                safe_action = "/".join(SecurityGuard.sanitize_segment(p) for p in self._action_parts[1:])
                if id_val is None:
                    # Shift logic allowing 'action_id=123' to act as primary ID
                    id_val = action_id
                    action_id = safe_action
                elif action_id is not None:
                    action_id = f"{safe_action}/{SecurityGuard.sanitize_segment(action_id)}"
                else:
                    action_id = safe_action

        return url, id_val, action_id

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
        version = self.client.config.version

        # Test Parity DX warning:
        if version == "v3" and self._name_lower == "templates":
            warnings.warn(
                "Mailjet API Ambiguity: Email API (v3) uses singular '/template'", DeprecationWarning, stacklevel=2
            )

        base_url = self.client.config.api_url.rstrip("/")

        # 1. Route Resolution Strategy
        if self.name in ROUTE_MAP:
            url, id_val, action_id = self._resolve_registry_route(base_url, version, id_val, action_id)
        else:
            url, id_val, action_id = self._resolve_dynamic_route(base_url, version, id_val, action_id)

        # 2. Final append of remaining dynamically passed IDs
        if id_val is not None:
            url = f"{url}/{SecurityGuard.sanitize_segment(id_val)}"

        if action_id is not None:
            if self.name in ROUTE_MAP or len(self._action_parts) == 1:
                # Raw user input appended dynamically
                url = f"{url}/{SecurityGuard.sanitize_segment(action_id)}"
            else:
                # Already composited/sanitized via dynamic action logic
                url = f"{url}/{action_id}"

        return url

    def _build_headers(self, custom_headers: dict[str, str] | None = None) -> dict[str, str]:
        """Build headers based on the endpoint requirements.

        Args:
            custom_headers (dict[str, str] | None): Custom headers to merge.

        Returns:
            dict[str, str]: The composed dictionary of HTTP headers.
        """
        base_headers = _TEXT_HEADERS if self._name_lower.endswith("_csvdata") else _JSON_HEADERS

        if custom_headers:
            clean_custom = SecurityGuard.sanitize_headers(custom_headers)
            merged = dict(base_headers)
            merged.update(clean_custom)
            return merged
        return dict(base_headers)

    def __call__(
        self,
        method: HttpMethod = "GET",
        id: int | str | None = None,
        data: PayloadType = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        timeout: TimeoutType = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute the specific HTTP method on the constructed endpoint.

        Args:
            method (HttpMethod): The HTTP method to use (default: "GET").
            id (int | str | None): The primary resource ID.
            data (PayloadType): Request payload.
            filters (dict[str, Any] | None): Query string URL parameters.
            action_id (int | str | None): Sub-action ID.
            timeout (TimeoutType): Request timeout.
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The resulting HTTP response from the request execution.
        """
        # Pop deprecated/HTTP kwargs safely
        headers = kwargs.pop("headers", None)
        ensure_ascii = kwargs.pop("ensure_ascii", None)
        data_encoding = kwargs.pop("data_encoding", None)

        if ensure_ascii is not None or data_encoding is not None:
            warnings.warn("'ensure_ascii' and 'data_encoding' are deprecated.", DeprecationWarning, stacklevel=2)

            # Include 'list' to ensure batch payloads (arrays) are serialized properly
            # for users relying on legacy encoding arguments.
            if isinstance(data, (dict, list)):
                # Legacy behavior emulation: force serialize data directly into string/bytes payload
                data_str = json.dumps(data, ensure_ascii=ensure_ascii if ensure_ascii is not None else True)
                data = data_str.encode(data_encoding) if data_encoding else data_str

        return self.client.api_call(
            method=method,
            url=self._build_url(id_val=id, action_id=action_id),
            headers=self._build_headers(headers),
            data=data,
            filters=filters,
            timeout=timeout,
            **kwargs,
        )

    def get(
        self,
        id: int | str | None = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a GET request.

        Args:
            id (int | str | None): The primary resource ID.
            filters (dict[str, Any] | None): Query string URL parameters.
            action_id (int | str | None): Sub-action ID.
            **kwargs (Any): Additional args passed to requests.

        Returns:
            requests.Response: The resulting HTTP response for the GET request.
        """
        return self(method="GET", id=id, filters=filters, action_id=action_id, **kwargs)

    def stream(
        self,
        id: int | str | None = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        chunk_size: int = 1000,
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """Automatically paginates over GET requests yielding resource dictionaries.

        Args:
            id (int | str | None): The primary resource ID.
            filters (dict[str, Any] | None): Query string URL parameters.
            action_id (int | str | None): Sub-action ID.
            chunk_size (int): Objects returned per loop (Limit). Defaults to 1000.
            **kwargs (Any): Additional args passed to requests.

        Yields:
            dict[str, Any]: Individual resource objects from the paginated API response.
        """
        # Prevent infinite CPU/Network loops if 0 or negative numbers are passed
        if chunk_size <= 0:
            msg = "stream() chunk_size must be a strictly positive integer."
            raise ValueError(msg)

        current_filters = dict(filters) if filters else {}
        current_filters["Limit"] = chunk_size

        # Respect user-provided offsets to allow stream resumption.
        # Cast to int to prevent TypeError when adding chunk_size later.
        # Protect against 'None' values throwing a TypeError when cast to int
        offset_val = current_filters.get("Offset")
        current_filters["Offset"] = int(offset_val) if offset_val is not None else 0

        while True:
            response = self.get(id=id, filters=current_filters, action_id=action_id, **kwargs)
            body = response.json()
            data = body.get("Data", [])

            yield from data

            # Break early if we've reached the absolute end
            if not data or len(data) < chunk_size:
                break

            current_filters["Offset"] += chunk_size

    def create(
        self,
        data: PayloadType = None,
        id: int | str | None = None,
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a POST request to create a resource.

        Args:
            data (PayloadType): Request payload.
            id (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.
            ensure_ascii (bool | None): Ensure ASCII serialization (Deprecated).
            data_encoding (str | None): Data encoding string (Deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response containing the created entity representation.
        """
        return self(
            method="POST",
            id=id,
            data=data,
            action_id=action_id,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def update(
        self,
        id: int | str,
        data: PayloadType = None,
        action_id: int | str | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a PUT request to update a resource.

        Args:
            id (int | str): The primary resource ID.
            data (PayloadType): Updated payload.
            action_id (int | str | None): The sub-action ID.
            ensure_ascii (bool | None): Ensure ASCII serialization (Deprecated).
            data_encoding (str | None): Data encoding string (Deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response for the updated resource context.
        """
        return self(
            method="PUT",
            id=id,
            data=data,
            action_id=action_id,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def delete(self, id: int | str, action_id: int | str | None = None, **kwargs: Any) -> requests.Response:
        """Perform a DELETE request to remove a resource.

        Args:
            id (int | str): The primary resource ID.
            action_id (int | str | None): The sub-action ID.
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response representing the deletion confirmation.
        """
        return self(method="DELETE", id=id, action_id=action_id, **kwargs)
