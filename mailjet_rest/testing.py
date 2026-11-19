"""In-memory test doubles for Mailjet SDK downstream unit testing."""

from __future__ import annotations

import sys
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from mailjet_rest.errors import raise_mapped_http_error


if TYPE_CHECKING:
    from types import TracebackType

    from mailjet_rest.types import HeadersMapping, HttpMethod, PayloadType, QueryFilters, ResourceId

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


__all__ = ["MockEndpoint", "MockMailjetClient", "MockResponse"]


@dataclass(slots=True)
class MockResponse:
    """In-memory response object mimicking ``requests.Response`` / ``httpx2.Response``."""

    status_code: int = 200
    _payload: dict[str, Any] = field(default_factory=lambda: {"Count": 0, "Total": 0, "Data": []})
    text: str = ""

    def json(self) -> dict[str, Any]:
        """Return a shallow copy of the synthetic JSON payload.

        Returns:
            dict[str, Any]: Synthetic Mailjet API response body.
        """
        return dict(self._payload)

    def raise_for_status(self) -> None:
        """Raise the matching Mailjet SDK API error when ``status_code >= 400``."""
        if self.status_code >= 400:
            raise_mapped_http_error(self, RuntimeError(f"Mock HTTP {self.status_code}"))


@dataclass(slots=True)
class MockEndpoint:
    """Recorded endpoint proxy returned by dynamic attribute access on :class:`MockMailjetClient`."""

    client: MockMailjetClient
    name: str

    def _record(
        self,
        method: HttpMethod,
        *,
        id: ResourceId | None = None,
        action_id: ResourceId | None = None,
        data: PayloadType = None,
        filters: QueryFilters | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        recorded_data = dict(data) if isinstance(data, Mapping) and not isinstance(data, dict) else data
        record: dict[str, Any] = {
            "endpoint": self.name,
            "method": method,
            "id": id,
            "action_id": action_id,
            "data": recorded_data,
            "filters": dict(filters) if filters is not None else None,
        }
        if headers is not None:
            record["headers"] = dict(headers)
        if kwargs:
            record["kwargs"] = dict(kwargs)
        self.client.sent_requests.append(record)
        status = self.client.default_status
        return MockResponse(
            status_code=status,
            _payload={
                "Status": "success" if status < 400 else "error",
                "StatusCode": status,
                "Count": 0,
                "Total": 0,
                "Data": [],
            },
        )

    def __call__(
        self,
        method: HttpMethod = "GET",
        id: ResourceId | None = None,
        data: PayloadType = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        """Record an endpoint invocation and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record(
            method,
            id=id,
            action_id=action_id,
            data=data,
            filters=filters,
            headers=headers,
            **kwargs,
        )

    def get(
        self,
        id: ResourceId | None = None,
        filters: QueryFilters | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        """Record a mock GET request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record("GET", id=id, action_id=action_id, filters=filters, headers=headers, **kwargs)

    def create(
        self,
        data: PayloadType = None,
        id: ResourceId | None = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        """Record a mock POST request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record("POST", id=id, action_id=action_id, data=data, headers=headers, **kwargs)

    def update(
        self,
        id: ResourceId | None = None,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        """Record a mock PUT request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record("PUT", id=id, action_id=action_id, data=data, headers=headers, **kwargs)

    def patch(
        self,
        id: ResourceId,
        data: PayloadType = None,
        action_id: ResourceId | None = None,
        headers: HeadersMapping | None = None,
        **kwargs: Any,
    ) -> MockResponse:
        """Record a mock PATCH request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record("PATCH", id=id, action_id=action_id, data=data, headers=headers, **kwargs)

    def delete(self, id: ResourceId, action_id: ResourceId | None = None, **kwargs: Any) -> MockResponse:
        """Record a mock DELETE request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        return self._record("DELETE", id=id, action_id=action_id, **kwargs)


@dataclass(slots=True)
class MockMailjetClient:
    """Drop-in in-memory Mailjet test double recording sent payloads."""

    sent_requests: list[dict[str, Any]] = field(default_factory=list)
    default_status: int = 200

    def create(self, *, data: dict[str, Any]) -> dict[str, Any]:
        """Record a payload directly and return a synthetic Mailjet status dict.

        Returns:
            dict[str, Any]: Synthetic response containing ``Status`` and ``StatusCode``.
        """
        self.sent_requests.append({"data": data})
        return {"Status": "success", "StatusCode": self.default_status}

    def __getattr__(self, name: str) -> MockEndpoint:
        """Resolve an arbitrary Mailjet endpoint proxy without network I/O.

        Returns:
            MockEndpoint: Recorded endpoint test double bound to this client.
        """
        if name.startswith("_"):
            msg = f"'{self.__class__.__name__}' object has no attribute '{name}'"
            raise AttributeError(msg)
        return MockEndpoint(client=self, name=name)

    def close(self) -> None:
        """Close the mock client cleanly (no-op)."""

    async def aclose(self) -> None:
        """Asynchronously close the mock client cleanly (no-op)."""

    def __enter__(self) -> Self:
        """Enter the synchronous context manager.

        Returns:
            Self: The active mock client instance.
        """
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the synchronous context manager."""
        _ = (exc_type, exc_val, exc_tb)
        self.close()

    async def __aenter__(self) -> Self:
        """Enter the asynchronous context manager.

        Returns:
            Self: The active mock client instance.
        """
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> None:
        """Exit the asynchronous context manager."""
        _ = (exc_type, exc_val, exc_tb)
        await self.aclose()
