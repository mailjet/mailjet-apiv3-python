"""API Endpoint routing and request building."""

from __future__ import annotations

import json
import sys
import warnings
from typing import TYPE_CHECKING, Any

from mailjet_rest.errors import MailjetApiError
from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP
from mailjet_rest.types import _JSON_HEADERS, _TEXT_HEADERS, HttpMethod, PayloadType, TimeoutType
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator, Mapping
    from typing import Protocol

    import httpx2
    import requests

    class _SyncClientProtocol(Protocol):
        config: Any

        def api_call(
            self,
            method: HttpMethod,
            url: str,
            filters: dict[str, Any] | None = None,
            data: PayloadType = None,
            headers: Mapping[str, str | None] | None = None,
            timeout: TimeoutType = None,
            **kwargs: Any,
        ) -> requests.Response:
            raise NotImplementedError

    class _AsyncClientProtocol(Protocol):
        config: Any

        async def api_call(
            self,
            method: HttpMethod,
            url: str,
            filters: dict[str, Any] | None = None,
            data: PayloadType = None,
            headers: Mapping[str, str | None] | None = None,
            timeout: TimeoutType = None,
            **kwargs: Any,
        ) -> httpx2.Response:
            raise NotImplementedError


__all__ = ["AsyncEndpoint", "BaseEndpoint", "Endpoint"]


class BaseEndpoint:
    """Shared base implementation for synchronous and asynchronous Mailjet endpoints.

    Dynamically binds to the HTTP client and coordinates URL generation,
    handling API resource mappings via the strict ROUTE_MAP.
    """

    __slots__ = ("_action_parts", "_name_lower", "_resource_lower", "client", "name")

    # Mailjet API pagination ceiling (https://dev.mailjet.com/docs/api-reference#pagination--sorting)
    MAX_LIMIT: int = 1000

    def __init__(self, client: Any, name: str) -> None:
        """Initialize the endpoint handler with the parent client and route name."""
        self.client: Any = client
        self.name = name
        self._name_lower = name.lower()
        parts = name.split("_")

        # Base resource ignores CamelCase-to-dash conversion
        self._resource_lower = parts[0].lower()
        self._action_parts = [self._resource_lower]

        # Re-implement camelCase-to-dash conversion natively for sub-actions
        if len(parts) > 1:
            for part in parts[1:]:
                dashed = "".join("-" + c.lower() if c.isupper() else c for c in part)
                self._action_parts.append(dashed.lstrip("-"))

    def __repr__(self) -> str:
        """Return a readable representation of this endpoint wrapper.

        Returns:
            str: Formatted endpoint representation.
        """
        return f"<{self.__class__.__name__} name={self.name!r}>"

    @staticmethod
    def _external_stacklevel() -> int:
        package_root = __name__.partition(".")[0]
        depth = 1
        try:
            frame = sys._getframe(depth)  # ruff: ignore[private-member-access]
        except (AttributeError, ValueError):
            return 2
        while frame is not None:
            mod_name = frame.f_globals.get("__name__", "")
            if mod_name == package_root or mod_name.startswith(f"{package_root}."):
                depth += 1
                frame = frame.f_back
            else:
                return depth
        return depth

    def _check_deprecation(self) -> None:
        """Emit a non-breaking warning when a deprecated route is invoked."""
        target = self._name_lower if self._name_lower in DEPRECATION_ADVISORY else self._resource_lower
        if target in DEPRECATION_ADVISORY:
            replacement = DEPRECATION_ADVISORY[target]
            warnings.warn(
                f"Endpoint '{target}' is deprecated in the Mailjet API. Migrate to '{replacement}'.",
                DeprecationWarning,
                stacklevel=self._external_stacklevel(),
            )

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
            safe_resource = SecurityGuard.sanitize_segment(self._resource_lower)
            url = f"{base_url}/{version}/REST/{safe_resource}"
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
        self._check_deprecation()
        raw_version = self.client.config.version
        version = raw_version if raw_version in {"v1", "v3", "v3.1"} else SecurityGuard.sanitize_segment(raw_version)

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

    def _build_headers(self, custom_headers: Mapping[str, str | None] | None = None) -> dict[str, str | None]:
        """Build headers based on the endpoint requirements.

        Args:
            custom_headers: Custom headers to merge.

        Returns:
            dict[str, str | None]: The composed dictionary of HTTP headers.
        """
        base_headers = _TEXT_HEADERS if self._name_lower.endswith("_csvdata") else _JSON_HEADERS

        if custom_headers:
            clean_custom = SecurityGuard.sanitize_headers(dict(custom_headers))
            return {**base_headers, **clean_custom}
        return dict(base_headers)

    @staticmethod
    def _cast_query_param(orig_ref: Any, raw_values: Any) -> Any:
        """Cast query string values to match the target filter parameter type.

        Handles single values or lists from urllib.parse.parse_qs and casts them
        to bool, int, float, list, tuple, set, or str based on orig_ref.

        Args:
            orig_ref: Reference value or type indicating the intended target type.
            raw_values: List of string values or a single scalar value.

        Returns:
            The parsed value cast to the target type.
        """
        vals = list(raw_values) if isinstance(raw_values, (list, tuple, set)) else [raw_values]

        if not vals:
            empty_defaults: dict[type, Any] = {
                bool: False,
                int: 0,
                float: 0.0,
                list: [],
                tuple: (),
                set: set(),
            }
            return empty_defaults.get(type(orig_ref), "")

        first_val = vals[0]
        if isinstance(orig_ref, bool):
            return str(first_val).strip().lower() in {"true", "1", "yes", "t"}

        if isinstance(orig_ref, (int, float)) and isinstance(first_val, bool):
            msg = "Boolean value is not a valid numeric query parameter."
            raise TypeError(msg)

        converters: dict[type, Any] = {
            int: lambda: int(first_val),
            float: lambda: float(first_val),
            list: lambda: list(vals),
            tuple: lambda: tuple(vals),
            set: lambda: set(vals),
        }
        converter = converters.get(type(orig_ref))
        if converter:
            return converter()

        return first_val if len(vals) == 1 else vals

    @classmethod
    def _normalize_stream_filters(
        cls, filters: Mapping[str, Any] | None, chunk_size: int
    ) -> tuple[dict[str, Any], int]:
        """Normalize filter keys and extract initial offset for pagination.

        Returns:
            tuple[dict[str, Any], int]: A tuple containing the sanitized filters
            dictionary (with Limit set) and the validated starting offset.
        """
        current_filters = dict(filters) if filters else {}
        raw_offset = current_filters.pop("offset", None)
        if raw_offset is None:
            raw_offset = current_filters.get("Offset")

        try:
            current_offset: int = cls._cast_query_param(0, raw_offset) if raw_offset is not None else 0
        except (ValueError, TypeError) as e:
            msg = f"stream() Offset filter must be an integer, got: {raw_offset!r}"
            raise ValueError(msg) from e

        if current_offset < 0:
            msg = f"stream() Offset filter must be a non-negative integer, got: {current_offset}"
            raise ValueError(msg)

        # Clean both 'limit' and 'Limit' from input filters so chunk_size governs the page window
        current_filters.pop("limit", None)
        current_filters.pop("Limit", None)
        current_filters["Limit"] = chunk_size

        return current_filters, current_offset

    @classmethod
    def _validate_stream_args(cls, method: HttpMethod, chunk_size: int, max_items: int | None) -> None:
        if method.upper() != "GET":
            msg = f"stream() is designed for GET requests only, got {method}"
            raise ValueError(msg)

        if isinstance(chunk_size, bool) or not isinstance(chunk_size, int) or chunk_size <= 0:
            msg = "stream() chunk_size must be a strictly positive integer."
            raise ValueError(msg)

        if chunk_size > cls.MAX_LIMIT:
            msg = (
                f"stream() chunk_size ({chunk_size}) exceeds Mailjet's maximum Limit of {cls.MAX_LIMIT}. "
                f"Set chunk_size <= {cls.MAX_LIMIT}."
            )
            raise ValueError(msg)

        if max_items is not None and (isinstance(max_items, bool) or not isinstance(max_items, int) or max_items < 0):
            msg = "stream() max_items must be a non-negative integer or None."
            raise ValueError(msg)

    @staticmethod
    def _parse_stream_page(response: Any) -> list[dict[str, Any]]:
        status_code = int(getattr(response, "status_code", 0) or 0)
        response_body = str(getattr(response, "text", "") or "")[:500]
        try:
            body = response.json()
        except (ValueError, AttributeError) as e:
            msg = "Malformed JSON body returned during stream() pagination."
            raise MailjetApiError(msg, status_code=status_code, response_body=response_body) from e

        if not isinstance(body, dict):
            msg = "Expected JSON object in stream() response."
            raise MailjetApiError(msg, status_code=status_code, response_body=response_body)

        raw_data = body.get("Data")
        if raw_data is None:
            return []
        if not isinstance(raw_data, list):
            msg = "Expected 'Data' list in stream() response."
            raise MailjetApiError(msg, status_code=status_code, response_body=response_body)
        return raw_data

    def _prepare_call_args(
        self,
        id: int | str | None,
        data: PayloadType,
        action_id: int | str | None,
        headers: Mapping[str, str | None] | None,
        kwargs: dict[str, Any],
    ) -> tuple[str, dict[str, str | None], PayloadType]:
        """Prepare URL, sanitized headers, and legacy-serialized payload for sync/async calls.

        Returns:
            tuple[str, dict[str, str | None], PayloadType]: Resolved URL, sanitized headers, and payload.
        """
        # Pop deprecated/HTTP kwargs safely without overwriting the explicit 'headers' argument
        if headers is None:
            headers = kwargs.pop("headers", None)
        else:
            kwargs.pop("headers", None)

        ensure_ascii = kwargs.pop("ensure_ascii", None)
        data_encoding = kwargs.pop("data_encoding", None)

        if ensure_ascii is not None or data_encoding is not None:
            warnings.warn(
                "'ensure_ascii' and 'data_encoding' are deprecated.",
                DeprecationWarning,
                stacklevel=self._external_stacklevel(),
            )

            # Include 'list' to ensure batch payloads (arrays) are serialized properly
            # for users relying on legacy encoding arguments.
            if isinstance(data, (dict, list)):
                # Legacy behavior emulation: force serialize data directly into string/bytes payload
                data_str = json.dumps(data, ensure_ascii=ensure_ascii if ensure_ascii is not None else True)
                data = data_str.encode(data_encoding) if data_encoding else data_str

        merged_headers = self._build_headers(headers)
        url = self._build_url(id_val=id, action_id=action_id)
        return url, merged_headers, data

    def _validate_delete_id(self, id: int | str) -> None:
        if id is None or isinstance(id, bool) or (isinstance(id, str) and not id.strip()):
            msg = f"{self.__class__.__name__}.delete() requires a non-empty, non-boolean resource 'id'."
            raise ValueError(msg)


class Endpoint(BaseEndpoint):
    """Represents a specific Mailjet REST resource path for synchronous requests."""

    __slots__ = ()
    client: _SyncClientProtocol

    def __call__(
        self,
        method: HttpMethod = "GET",
        id: int | str | None = None,
        data: PayloadType = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        timeout: TimeoutType = None,
        headers: Mapping[str, str | None] | None = None,
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
            headers (Mapping[str, str | None] | None): Custom HTTP request headers.
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The resulting HTTP response from the request execution.
        """
        url, merged_headers, prepared_data = self._prepare_call_args(id, data, action_id, headers, kwargs)
        return self.client.api_call(
            method=method,
            url=url,
            headers=merged_headers,
            data=prepared_data,
            filters=filters,
            timeout=timeout,
            **kwargs,
        )

    def get(
        self,
        id: int | str | None = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a GET request on the constructed endpoint.

        Args:
            id: The primary resource ID.
            filters: Query string URL parameters.
            action_id: Sub-action ID.
            headers: Custom HTTP request headers.
            **kwargs: Additional arguments passed to the request layer.

        Returns:
            requests.Response: The resulting HTTP response from the GET request.
        """
        return self(method="GET", id=id, filters=filters, action_id=action_id, headers=headers, **kwargs)

    def stream(
        self,
        id: int | str | None = None,
        filters: Mapping[str, Any] | None = None,
        action_id: int | str | None = None,
        chunk_size: int = 1000,
        method: HttpMethod = "GET",
        *,
        max_items: int | None = None,
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """Automatically paginates over GET requests yielding resource dictionaries.

        Args:
            id: The primary resource ID.
            filters: Query string URL parameters. Accepts dicts, MappingProxy, or parse_qs multi-dicts.
            action_id: Sub-action ID.
            chunk_size: Objects returned per loop (Limit). Defaults to 1000 (Mailjet max limit).
            method: The HTTP method to use (must be GET).
            max_items: Optional upper bound on total yielded records across all pages.
            **kwargs: Additional arguments passed to requests.

        Yields:
            dict[str, Any]: Individual resource objects from the paginated API response.
        """
        self._validate_stream_args(method, chunk_size, max_items)
        current_filters, current_offset = self._normalize_stream_filters(filters, chunk_size)

        if max_items == 0:
            return

        yielded = 0
        while True:
            page_limit = min(chunk_size, max_items - yielded) if max_items is not None else chunk_size
            current_filters["Limit"] = page_limit
            current_filters["Offset"] = current_offset
            response = self.get(id=id, filters=current_filters.copy(), action_id=action_id, **kwargs)

            if hasattr(response, "raise_for_status"):
                response.raise_for_status()

            data = self._parse_stream_page(response)
            for item in data:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return

            # REST endpoints report a page-local Total unless countOnly is used.
            # Continue through full pages rather than treating it as a collection size.
            if not data or len(data) < page_limit:
                break

            current_offset += len(data)

    def create(
        self,
        data: PayloadType = None,
        id: int | str | None = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a POST request to create a resource.

        Args:
            data (PayloadType): Request payload.
            id (int | str | None): The primary resource ID.
            action_id (int | str | None): The sub-action ID.
            headers (dict[str, str] | None): Custom headers.
            ensure_ascii (bool | None): Ensure ASCII encoding (deprecated).
            data_encoding (str | None): Data encoding (deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response containing the created entity representation.
        """
        return self(
            method="POST",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def update(
        self,
        id: int | str,
        data: PayloadType = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a PUT request to update a resource.

        Args:
            id (int | str): The primary resource ID.
            data (PayloadType): Request payload.
            action_id (int | str | None): The sub-action ID.
            headers (dict[str, str] | None): Custom headers.
            ensure_ascii (bool | None): Ensure ASCII encoding (deprecated).
            data_encoding (str | None): Data encoding (deprecated).
            **kwargs (Any): Additional arguments.

        Returns:
            requests.Response: The HTTP response for the updated resource context.
        """
        return self(
            method="PUT",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    def patch(
        self,
        id: int | str,
        data: PayloadType = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a PATCH request to partially update a resource.

        Args:
            id: The primary resource ID.
            data: Request payload.
            action_id: The sub-action ID.
            headers: Custom headers.
            ensure_ascii: Ensure ASCII encoding (deprecated).
            data_encoding: Data encoding (deprecated).
            **kwargs: Additional arguments.

        Returns:
            requests.Response: The HTTP response for the patched resource context.
        """
        return self(
            method="PATCH",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
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
        self._validate_delete_id(id)
        return self(method="DELETE", id=id, action_id=action_id, **kwargs)


class AsyncEndpoint(BaseEndpoint):
    """Represents a specific Mailjet REST resource path for asynchronous requests."""

    __slots__ = ()
    client: _AsyncClientProtocol

    async def __call__(
        self,
        method: HttpMethod = "GET",
        id: int | str | None = None,
        data: PayloadType = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        timeout: TimeoutType = None,
        headers: Mapping[str, str | None] | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Execute the specific HTTP method asynchronously on the constructed endpoint.

        Args:
            method: The HTTP method to use (default: "GET").
            id: The primary resource ID.
            data: Request payload.
            filters: Query string URL parameters.
            action_id: Sub-action ID.
            timeout: Request timeout.
            headers: Custom HTTP request headers.
            **kwargs: Additional arguments.

        Returns:
            httpx2.Response: The resulting HTTP response from the request execution.
        """
        url, merged_headers, prepared_data = self._prepare_call_args(id, data, action_id, headers, kwargs)
        return await self.client.api_call(
            method=method,
            url=url,
            headers=merged_headers,
            data=prepared_data,
            filters=filters,
            timeout=timeout,
            **kwargs,
        )

    async def get(
        self,
        id: int | str | None = None,
        filters: dict[str, Any] | None = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous GET request on the constructed endpoint.

        Args:
            id: The primary resource ID.
            filters: Query string URL parameters.
            action_id: Sub-action ID.
            headers: Custom HTTP request headers.
            **kwargs: Additional arguments passed to the request layer.

        Returns:
            httpx2.Response: The resulting HTTP response from the GET request.
        """
        return await self(method="GET", id=id, filters=filters, action_id=action_id, headers=headers, **kwargs)

    async def stream(
        self,
        id: int | str | None = None,
        filters: Mapping[str, Any] | None = None,
        action_id: int | str | None = None,
        chunk_size: int = 1000,
        method: HttpMethod = "GET",
        *,
        max_items: int | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Automatically paginate asynchronously over GET requests yielding resource dictionaries.

        Args:
            id: The primary resource ID.
            filters: Query string URL parameters. Accepts dicts, MappingProxy, or parse_qs multi-dicts.
            action_id: Sub-action ID.
            chunk_size: Objects returned per loop (Limit). Defaults to 1000 (Mailjet max limit).
            method: The HTTP method to use (must be GET).
            max_items: Optional upper bound on total yielded records across all pages.
            **kwargs: Additional arguments passed to httpx2.

        Yields:
            dict[str, Any]: Individual resource objects from the paginated API response.
        """
        self._validate_stream_args(method, chunk_size, max_items)
        current_filters, current_offset = self._normalize_stream_filters(filters, chunk_size)

        if max_items == 0:
            return

        yielded = 0
        while True:
            page_limit = min(chunk_size, max_items - yielded) if max_items is not None else chunk_size
            current_filters["Limit"] = page_limit
            current_filters["Offset"] = current_offset
            response = await self.get(id=id, filters=current_filters.copy(), action_id=action_id, **kwargs)

            if hasattr(response, "raise_for_status"):
                response.raise_for_status()

            data = self._parse_stream_page(response)
            for item in data:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return

            if not data or len(data) < page_limit:
                break

            current_offset += len(data)

    async def create(
        self,
        data: PayloadType = None,
        id: int | str | None = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous POST request to create a resource.

        Args:
            data: Request payload.
            id: The primary resource ID.
            action_id: The sub-action ID.
            headers: Custom headers.
            ensure_ascii: Ensure ASCII encoding (deprecated).
            data_encoding: Data encoding (deprecated).
            **kwargs: Additional arguments.

        Returns:
            httpx2.Response: The HTTP response containing the created entity representation.
        """
        return await self(
            method="POST",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    async def update(
        self,
        id: int | str,
        data: PayloadType = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous PUT request to update a resource.

        Args:
            id: The primary resource ID.
            data: Request payload.
            action_id: The sub-action ID.
            headers: Custom headers.
            ensure_ascii: Ensure ASCII encoding (deprecated).
            data_encoding: Data encoding (deprecated).
            **kwargs: Additional arguments.

        Returns:
            httpx2.Response: The HTTP response for the updated resource context.
        """
        return await self(
            method="PUT",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    async def patch(
        self,
        id: int | str,
        data: PayloadType = None,
        action_id: int | str | None = None,
        headers: Mapping[str, str | None] | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous PATCH request to partially update a resource.

        Args:
            id: The primary resource ID.
            data: Request payload.
            action_id: The sub-action ID.
            headers: Custom headers.
            ensure_ascii: Ensure ASCII encoding (deprecated).
            data_encoding: Data encoding (deprecated).
            **kwargs: Additional arguments.

        Returns:
            httpx2.Response: The HTTP response for the patched resource context.
        """
        return await self(
            method="PATCH",
            id=id,
            data=data,
            action_id=action_id,
            headers=headers,
            ensure_ascii=ensure_ascii,
            data_encoding=data_encoding,
            **kwargs,
        )

    async def delete(self, id: int | str, action_id: int | str | None = None, **kwargs: Any) -> httpx2.Response:
        """Perform an asynchronous DELETE request to remove a resource.

        Args:
            id: The primary resource ID.
            action_id: The sub-action ID.
            **kwargs: Additional arguments.

        Returns:
            httpx2.Response: The HTTP response representing the deletion confirmation.
        """
        self._validate_delete_id(id)
        return await self(method="DELETE", id=id, action_id=action_id, **kwargs)
