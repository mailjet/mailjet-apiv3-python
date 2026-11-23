"""Retry policy, Retry-After HTTP-date parsing, and seekable stream rewind helpers."""

from __future__ import annotations

import math
import secrets
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Any, Final

from urllib3.util.retry import Retry

from mailjet_rest.errors import CriticalApiError


if TYPE_CHECKING:
    import logging
    from collections.abc import Awaitable, Callable


__all__ = [
    "DEFAULT_RETRY_STRATEGY",
    "MAX_RETRY_DELAY",
    "RETRY_ALLOWED_METHODS",
    "TRANSIENT_STATUS_CODES",
    "JitterRetry",
    "compute_retry_delay",
    "parse_retry_after_http_date",
    "reset_stream_pointers",
    "run_async_with_retries",
    "snapshot_stream_offsets",
]


TRANSIENT_STATUS_CODES: Final[frozenset[int]] = frozenset({429, 500, 502, 503, 504})
MAX_RETRY_DELAY: Final[float] = 60.0
RETRY_ALLOWED_METHODS: Final[tuple[str, ...]] = (
    "HEAD",
    "GET",
    "OPTIONS",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
)


class JitterRetry(Retry):
    """Custom retry policy with randomized full jitter to prevent Thundering Herd (429)."""

    def get_backoff_time(self) -> float:
        """Compute exponential backoff with randomized full jitter.

        Returns:
            float: Delay duration in seconds before retrying.
        """
        base_backoff = super().get_backoff_time()
        return secrets.SystemRandom().uniform(0, base_backoff) if base_backoff > 0 else 0


DEFAULT_RETRY_STRATEGY: Final[JitterRetry] = JitterRetry(
    total=3,
    backoff_factor=1,
    status_forcelist=sorted(TRANSIENT_STATUS_CODES),
    allowed_methods=list(RETRY_ALLOWED_METHODS),  # Mutations use safe idempotency keys
    raise_on_status=False,
)


def parse_retry_after_http_date(raw_header: str, *, max_delay: float = MAX_RETRY_DELAY) -> float | None:
    """Parse an RFC 9110 Retry-After HTTP-date header into bounded delay seconds.

    Returns:
        float | None: Clamped non-negative delay in seconds, or None if not a valid HTTP-date.
    """
    from datetime import datetime, timezone  # ruff: ignore[import-outside-top-level]
    from email.utils import parsedate_to_datetime  # ruff: ignore[import-outside-top-level]

    try:
        parsed_dt = parsedate_to_datetime(raw_header)
    except (TypeError, ValueError, OverflowError):
        return None
    if parsed_dt.tzinfo is None:
        parsed_dt = parsed_dt.replace(tzinfo=timezone.utc)
    delay = (parsed_dt - datetime.now(timezone.utc)).total_seconds()
    return min(max(0.0, delay), max_delay)


def compute_retry_delay(
    attempt: int,
    retry_after_header: str | None = None,
    *,
    max_delay: float = MAX_RETRY_DELAY,
) -> float:
    """Compute full-jitter exponential backoff or bounded Retry-After delay in seconds.

    Returns:
        float: Delay duration in seconds bounded by ``max_delay``.
    """
    if isinstance(retry_after_header, str):
        stripped = retry_after_header.strip()
        if stripped:
            try:
                parsed = float(stripped)
            except ValueError:
                date_delay = parse_retry_after_http_date(stripped, max_delay=max_delay)
                if date_delay is not None:
                    return date_delay
            else:
                if math.isfinite(parsed) and parsed >= 0:
                    return min(parsed, max_delay)

    bounded_exponent = max(0, min(attempt, 20))
    base_backoff = min(float(2**bounded_exponent), max_delay)
    return secrets.SystemRandom().uniform(0.0, base_backoff)


def _is_active_seekable_stream(item: Any) -> bool:
    seek_fn = getattr(item, "seek", None)
    if not callable(seek_fn) or getattr(item, "closed", False):
        return False
    seekable_fn = getattr(item, "seekable", None)
    return not callable(seekable_fn) or bool(seekable_fn())


def _iter_stream_nodes(data: Any, files: Any) -> list[Any]:
    nodes: list[Any] = []
    stack: list[tuple[Any, int]] = [(data, 0), (files, 0)]
    while stack:
        item, depth = stack.pop()
        if item is None or depth > 4:
            continue
        if _is_active_seekable_stream(item):
            nodes.append(item)
        elif isinstance(item, (Mapping, list, tuple)):
            children = item.values() if isinstance(item, Mapping) else item
            stack.extend((elem, depth + 1) for elem in children)
    return nodes


def snapshot_stream_offsets(data: Any, files: Any) -> dict[int, int]:
    """Capture initial seek positions for open seekable payload and multipart streams.

    Returns:
        dict[int, int]: Mapping from stream ``id()`` to initial offset.
    """
    offsets: dict[int, int] = {}
    for item in _iter_stream_nodes(data, files):
        tell_fn = getattr(item, "tell", None)
        if callable(tell_fn):
            with suppress(OSError, ValueError):
                pos = tell_fn()
                if isinstance(pos, int) and not isinstance(pos, bool):
                    offsets[id(item)] = pos
    return offsets


def reset_stream_pointers(
    data: Any,
    files: Any,
    offsets: Mapping[int, int] | None = None,
) -> None:
    """Rewind seekable payload and multipart file streams before retrying a request."""
    for item in _iter_stream_nodes(data, files):
        target_pos = offsets.get(id(item), 0) if offsets is not None else 0
        with suppress(OSError, ValueError):
            item.seek(target_pos)


async def _check_async_retry_response(
    response: Any,
    attempt: int,
    max_retries: int,
    method: str,
    url: str,
    *,
    log: logging.Logger,
    transient_status_codes: frozenset[int],
    max_delay: float,
) -> float | None:
    status = getattr(response, "status_code", None)
    if attempt >= max_retries or status not in transient_status_codes:
        return None
    resp_headers = getattr(response, "headers", None)
    retry_after = (
        resp_headers.get("Retry-After") or resp_headers.get("retry-after") if resp_headers is not None else None
    )
    delay = compute_retry_delay(attempt, retry_after, max_delay=max_delay)
    log.warning(
        "Transient HTTP %s on %s %s; retry %d/%d in %.2fs", status, method, url, attempt + 1, max_retries, delay
    )
    if not getattr(response, "is_closed", True):
        with suppress(Exception):
            await response.aclose()
    return delay


def _handle_retryable_exception(
    exc: Exception,
    attempt: int,
    max_retries: int,
    method: str,
    url: str,
    *,
    max_delay: float,
    log: logging.Logger,
) -> float:
    if attempt >= max_retries:
        raise exc
    delay = compute_retry_delay(attempt, max_delay=max_delay)
    log.warning(
        "Transient async transport error (%s) on %s %s; retry %d/%d in %.2fs",
        type(exc).__name__,
        method,
        url,
        attempt + 1,
        max_retries,
        delay,
    )
    return delay


async def run_async_with_retries(
    send_fn: Callable[[], Awaitable[Any]],
    httpx2_mod: Any,
    *,
    method: str,
    url: str,
    raw_retries: int,
    max_retries_limit: int,
    allowed_methods: tuple[str, ...],
    transient_status_codes: frozenset[int],
    max_delay: float,
    data: Any,
    files: Any,
    log: logging.Logger,
) -> Any:
    """Execute an async transport coroutine with full-jitter retries and stream rewind.

    Returns:
        Any: Final HTTP response returned by ``send_fn``.
    """
    import asyncio  # ruff: ignore[import-outside-top-level]

    if isinstance(raw_retries, bool) or not isinstance(raw_retries, int) or raw_retries < 0:
        msg = f"max_retries must be a non-negative integer, got {raw_retries!r}."
        raise ValueError(msg)
    max_retries = min(raw_retries, max_retries_limit) if method in allowed_methods else 0
    retryable_errors: tuple[type[Exception], ...] = (
        httpx2_mod.TimeoutException,
        httpx2_mod.NetworkError,
        httpx2_mod.RemoteProtocolError,
        httpx2_mod.ProxyError,
    )

    initial_offsets = snapshot_stream_offsets(data, files)
    for attempt in range(max_retries + 1):
        try:
            response = await send_fn()
        except (httpx2_mod.UnsupportedProtocol, httpx2_mod.DecodingError):
            raise
        except retryable_errors as exc:
            delay = _handle_retryable_exception(exc, attempt, max_retries, method, url, max_delay=max_delay, log=log)
        else:
            delay_or_done = await _check_async_retry_response(
                response,
                attempt,
                max_retries,
                method,
                url,
                log=log,
                transient_status_codes=transient_status_codes,
                max_delay=max_delay,
            )
            if delay_or_done is None:
                return response
            delay = delay_or_done

        await asyncio.sleep(delay)
        reset_stream_pointers(data, files, initial_offsets)

    msg = "Retry loop exited unexpectedly."  # pragma: no cover
    raise CriticalApiError(msg)  # pragma: no cover
