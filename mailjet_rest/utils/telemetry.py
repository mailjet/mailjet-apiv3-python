"""Sanitized telemetry extraction and API response logging helpers."""

from __future__ import annotations

import logging
from collections.abc import Mapping
from contextlib import suppress
from typing import TYPE_CHECKING, Any

from mailjet_rest.errors import MAX_ERROR_LOG_CHARS, sanitize_error_text
from mailjet_rest.types import _ALLOWED_TRACE_FIELDS
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from mailjet_rest.types import HeadersMapping


__all__ = ["extract_telemetry", "log_api_response", "record_debug_telemetry"]


def extract_telemetry(data: Any, _headers: HeadersMapping | None = None) -> tuple[str, dict[str, str]]:
    """Extract sanitized tracing identifiers for safe logging and structured telemetry.

    Returns:
        tuple[str, dict[str, str]]: Formatted trace suffix and structured telemetry attributes.
    """
    trace_ctx: list[str] = []
    structured_data: dict[str, str] = {}
    with suppress(Exception):
        if isinstance(data, (Mapping, list)):
            messages = data.get("Messages", [{}]) if isinstance(data, Mapping) else data
            target_dict = messages[0] if isinstance(messages, list) and messages else data

            if isinstance(target_dict, Mapping):
                for field in _ALLOWED_TRACE_FIELDS:
                    if val := target_dict.get(field) or (isinstance(data, Mapping) and data.get(field)):
                        clean_val = SecurityGuard.sanitize_log_trace(val)
                        trace_ctx.append(f"{field}={clean_val}")
                        structured_data[f"mailjet.{field.lower()}"] = clean_val

    return f" | Trace: [{' '.join(trace_ctx)}]" if trace_ctx else "", structured_data


def log_api_response(
    log: logging.Logger,
    method: str,
    url: str,
    response: Any,
    trace_str: str,
    *,
    max_chars: int = MAX_ERROR_LOG_CHARS,
) -> None:
    """Log formatted, truncated, and control-char-neutralized API lifecycle events."""
    status_code = getattr(response, "status_code", None)
    if isinstance(status_code, int) and status_code >= 400:
        safe_body = sanitize_error_text(getattr(response, "text", ""), max_chars=max_chars)
        log.error("API Error %s | %s %s%s | Response: %s", status_code, method, url, trace_str, safe_body)
    else:
        log.debug("API Success %s | %s %s%s", status_code or 200, method, url, trace_str)


def record_debug_telemetry(
    log: logging.Logger,
    method: str,
    url: str,
    response: Any,
    data: Any,
    headers: HeadersMapping | None,
) -> None:
    """Emit debug trace logs for successful API responses when DEBUG logging is active."""
    if getattr(response, "status_code", None) in {200, 201, 204} and log.isEnabledFor(logging.DEBUG):
        trace_suffix, _ = extract_telemetry(data, headers)
        log_api_response(log, method, url, response, trace_suffix)
