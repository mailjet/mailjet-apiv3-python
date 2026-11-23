"""In-memory test doubles for Mailjet SDK downstream unit testing."""

from __future__ import annotations

import sys
from collections.abc import Generator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, cast

from mailjet_rest.errors import raise_mapped_http_error
from mailjet_rest.utils.routing import validate_stream_args


if TYPE_CHECKING:
    from types import TracebackType

    from mailjet_rest.types import HeadersMapping, HttpMethod, PayloadType, QueryFilters, ResourceId, TimeoutType

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


__all__ = ["MockEndpoint", "MockMailjetClient", "MockResponse"]


class _ResolvedAwaitable:
    """Zero-overhead iterator completing ``await`` immediately with a precomputed value."""

    __slots__ = ("_value",)

    def __init__(self, value: Any) -> None:
        self._value = value

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> Any:
        raise StopIteration(self._value)


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

    def __await__(self) -> Generator[Any, None, Self]:
        """Allow ``MockResponse`` instances to be ``await``ed transparently in async tests.

        Returns:
            Generator[Any, None, Self]: Awaitable iterator resolving to ``self``.
        """
        return cast("Generator[Any, None, Self]", _ResolvedAwaitable(self))


class _MockStreamIterator:
    """Dual sync/async iterator yielded by :meth:`MockEndpoint.stream`."""

    __slots__ = ("_index", "_items")

    def __init__(self, items: tuple[dict[str, Any], ...] = ()) -> None:
        self._items = items
        self._index = 0

    def __iter__(self) -> Self:
        return self

    def __next__(self) -> dict[str, Any]:
        if self._index >= len(self._items):
            raise StopIteration
        item = self._items[self._index]
        self._index += 1
        return item

    def __aiter__(self) -> Self:
        return self

    async def __anext__(self) -> dict[str, Any]:
        try:
            return next(self)
        except StopIteration as exc:
            raise StopAsyncIteration from exc


class _MockPingResult:
    """Boolean-like ping probe result supporting both sync truth checks and ``await``."""

    __slots__ = ("_ok",)

    def __init__(self, ok: bool) -> None:
        self._ok = ok

    def __bool__(self) -> bool:
        return self._ok

    def __eq__(self, other: object) -> bool:
        if isinstance(other, (bool, _MockPingResult)):
            return self._ok is bool(other)
        return NotImplemented

    def __hash__(self) -> int:
        return hash(self._ok)

    def __repr__(self) -> str:
        return repr(self._ok)

    def __await__(self) -> Generator[Any, None, bool]:
        return cast("Generator[Any, None, bool]", _ResolvedAwaitable(self._ok))


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

    def _validate_required_id(self, id: ResourceId, action: str) -> None:
        if id is None or isinstance(id, bool) or (isinstance(id, str) and not id.strip()):
            msg = f"{self.__class__.__name__}.{action}() requires a non-empty, non-boolean resource 'id'."
            raise ValueError(msg)

    def delete(self, id: ResourceId, action_id: ResourceId | None = None, **kwargs: Any) -> MockResponse:
        """Record a mock DELETE request and return a synthetic response.

        Returns:
            MockResponse: In-memory mock HTTP response.
        """
        self._validate_required_id(id, "delete")
        return self._record("DELETE", id=id, action_id=action_id, **kwargs)

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
    ) -> _MockStreamIterator:
        """Record a paginated stream request and return a sync/async empty-safe iterator.

        Returns:
            _MockStreamIterator: Iterator supporting both ``for`` and ``async for``.
        """
        validate_stream_args(method, chunk_size, max_items)
        self._record(method, id=id, action_id=action_id, filters=filters, **kwargs)
        return _MockStreamIterator()


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

    def ping(self, timeout: TimeoutType = None) -> _MockPingResult:
        """Return synthetic reachability status usable synchronously or via ``await``.

        Returns:
            _MockPingResult: Truthy when ``default_status < 400``, awaitable to ``bool``.
        """
        _ = timeout
        return _MockPingResult(self.default_status < 400)

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
