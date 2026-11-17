"""API Endpoint routing and request building."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from mailjet_rest.utils.routing import (
    build_endpoint_headers,
    build_endpoint_url,
    cast_query_param,
    normalize_stream_filters,
    parse_stream_page,
    prepare_call_payload_and_headers,
    resolve_dynamic_route,
    resolve_registry_route,
    split_endpoint_parts,
    validate_stream_args,
)


if TYPE_CHECKING:
    from collections.abc import AsyncGenerator, Generator
    from typing import Protocol

    import httpx2
    import requests

    from mailjet_rest.types import (
        HeadersMapping,
        HttpMethod,
        PayloadType,
        QueryFilters,
        RequestHeaders,
        ResourceId,
        TimeoutType,
    )

    class _SyncClientProtocol(Protocol):
        config: Any

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
            raise NotImplementedError

    class _AsyncClientProtocol(Protocol):
        config: Any

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
            raise NotImplementedError


__all__ = ["AsyncEndpoint", "BaseEndpoint", "Endpoint"]


class BaseEndpoint:
    """Shared URL routing, header composition, and pagination base for sync and async endpoints."""

    __slots__ = ("_action_parts", "_name_lower", "_resource_lower", "client", "name")

    # Mailjet API pagination ceiling (https://dev.mailjet.com/docs/api-reference#pagination--sorting)
    MAX_LIMIT: int = 1000

    def __init__(self, client: Any, name: str) -> None:
        """Initialize the endpoint handler with the parent client and route name."""
        self.client: Any = client
        self.name = name
        self._name_lower, self._resource_lower, self._action_parts = split_endpoint_parts(name)

    def __repr__(self) -> str:
        """Return a readable representation of this endpoint wrapper.

        Returns:
            str: Formatted endpoint representation.
        """
        return f"<{self.__class__.__name__} name={self.name!r}>"

    def _resolve_registry_route(
        self, base_url: str, version: str, id_val: ResourceId | None, action_id: ResourceId | None
    ) -> tuple[str, ResourceId | None, ResourceId | None]:
        return resolve_registry_route(self.name, base_url, version, id_val, action_id)

    def _resolve_dynamic_route(
        self, base_url: str, version: str, id_val: ResourceId | None, action_id: ResourceId | None
    ) -> tuple[str, ResourceId | None, ResourceId | None]:
        return resolve_dynamic_route(
            self._name_lower,
            self._resource_lower,
            self._action_parts,
            base_url,
            version,
            id_val,
            action_id,
        )

    def _build_url(self, id_val: ResourceId | None = None, action_id: ResourceId | None = None) -> str:
        return build_endpoint_url(
            self.name,
            self._name_lower,
            self._resource_lower,
            self._action_parts,
            self.client.config.api_url,
            self.client.config.version,
            id_val=id_val,
            action_id=action_id,
        )

    def _build_headers(self, custom_headers: HeadersMapping | None = None) -> RequestHeaders:
        return build_endpoint_headers(self._name_lower, custom_headers)

    @staticmethod
    def _cast_query_param(orig_ref: Any, raw_values: Any) -> Any:
        return cast_query_param(orig_ref, raw_values)

    @classmethod
    def _normalize_stream_filters(cls, filters: QueryFilters | None, chunk_size: int) -> tuple[dict[str, Any], int]:
        return normalize_stream_filters(filters, chunk_size)

    @classmethod
    def _validate_stream_args(cls, method: HttpMethod, chunk_size: int, max_items: int | None) -> None:
        validate_stream_args(method, chunk_size, max_items, max_limit=cls.MAX_LIMIT)

    @staticmethod
    def _parse_stream_page(response: Any) -> list[dict[str, Any]]:
        return parse_stream_page(response)

    def _extract_stream_page(self, response: Any) -> list[dict[str, Any]]:
        if hasattr(response, "raise_for_status"):
            response.raise_for_status()
        return self._parse_stream_page(response)

    def _prepare_call_args(
        self,
        id: ResourceId | None,
        data: PayloadType,
        action_id: ResourceId | None,
        headers: HeadersMapping | None,
        kwargs: dict[str, Any],
    ) -> tuple[str, RequestHeaders, PayloadType]:
        merged_headers, prepared_data = prepare_call_payload_and_headers(self._name_lower, data, headers, kwargs)
        url = self._build_url(id_val=id, action_id=action_id)
        return url, merged_headers, prepared_data

    def _validate_delete_id(self, id: ResourceId) -> None:
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
        id: ResourceId | None = None,
        data: PayloadType = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        timeout: TimeoutType = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Execute an HTTP request against the constructed endpoint.

        Returns:
            requests.Response: Resulting synchronous HTTP response.
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
        id: ResourceId | None = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a synchronous GET request on this endpoint.

        Returns:
            requests.Response: Resulting HTTP response.
        """
        return self(method="GET", id=id, filters=filters, action_id=action_id, headers=headers, **kwargs)

    def stream(
        self,
        id: ResourceId | None = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        chunk_size: int = 1000,
        method: HttpMethod = "GET",
        *,
        max_items: int | None = None,
        **kwargs: Any,
    ) -> Generator[dict[str, Any], None, None]:
        """Paginate synchronously over GET requests yielding resource dictionaries.

        Yields:
            dict[str, Any]: Individual resource objects from paginated ``Data`` arrays.
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
            data = self._extract_stream_page(response)
            for item in data:
                yield item
                yielded += 1
                if max_items is not None and yielded >= max_items:
                    return
            # REST endpoints report a page-local Total unless countOnly is used; continue through full pages.
            if not data or len(data) < page_limit:
                break
            current_offset += len(data)

    def create(
        self,
        data: PayloadType = None,
        id: ResourceId | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a synchronous POST request to create a resource.

        Returns:
            requests.Response: Resulting HTTP response.
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
        id: ResourceId,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a synchronous PUT request to update a resource.

        Returns:
            requests.Response: Resulting HTTP response.
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
        id: ResourceId,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> requests.Response:
        """Perform a synchronous PATCH request to partially update a resource.

        Returns:
            requests.Response: Resulting HTTP response.
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

    def delete(self, id: ResourceId, action_id: ResourceId | None = None, **kwargs: Any) -> requests.Response:
        """Perform a synchronous DELETE request to remove a resource.

        Returns:
            requests.Response: Resulting HTTP response.
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
        id: ResourceId | None = None,
        data: PayloadType = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        timeout: TimeoutType = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Execute an asynchronous HTTP request against the constructed endpoint.

        Returns:
            httpx2.Response: Resulting asynchronous HTTP response.
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
        id: ResourceId | None = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous GET request on this endpoint.

        Returns:
            httpx2.Response: Resulting HTTP response.
        """
        return await self(method="GET", id=id, filters=filters, action_id=action_id, headers=headers, **kwargs)

    async def stream(
        self,
        id: ResourceId | None = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        chunk_size: int = 1000,
        method: HttpMethod = "GET",
        *,
        max_items: int | None = None,
        **kwargs: Any,
    ) -> AsyncGenerator[dict[str, Any], None]:
        """Paginate asynchronously over GET requests yielding resource dictionaries.

        Yields:
            dict[str, Any]: Individual resource objects from paginated ``Data`` arrays.
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
            data = self._extract_stream_page(response)
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
        id: ResourceId | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous POST request to create a resource.

        Returns:
            httpx2.Response: Resulting HTTP response.
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
        id: ResourceId,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous PUT request to update a resource.

        Returns:
            httpx2.Response: Resulting HTTP response.
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
        id: ResourceId,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        ensure_ascii: bool | None = None,
        data_encoding: str | None = None,
        **kwargs: Any,
    ) -> httpx2.Response:
        """Perform an asynchronous PATCH request to partially update a resource.

        Returns:
            httpx2.Response: Resulting HTTP response.
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

    async def delete(self, id: ResourceId, action_id: ResourceId | None = None, **kwargs: Any) -> httpx2.Response:
        """Perform an asynchronous DELETE request to remove a resource.

        Returns:
            httpx2.Response: Resulting HTTP response.
        """
        self._validate_delete_id(id)
        return await self(method="DELETE", id=id, action_id=action_id, **kwargs)
