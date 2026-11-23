"""Stateless endpoint URL compilation, query casting, and stream pagination helpers."""

from __future__ import annotations

import json
import sys
import warnings
from collections.abc import Mapping
from typing import TYPE_CHECKING, Any

from mailjet_rest.errors import MailjetApiError
from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP
from mailjet_rest.types import _CSV_HEADERS, _JSON_HEADERS, _TEXT_HEADERS
from mailjet_rest.utils.guardrails import SecurityGuard


if TYPE_CHECKING:
    from mailjet_rest.types import (
        HeadersMapping,
        HttpMethod,
        PayloadType,
        QueryFilters,
        RequestHeaders,
        ResourceId,
    )


__all__ = [
    "build_endpoint_headers",
    "build_endpoint_url",
    "cast_query_param",
    "emit_deprecation_if_needed",
    "external_stacklevel",
    "normalize_stream_filters",
    "parse_stream_page",
    "prepare_call_payload_and_headers",
    "resolve_dynamic_route",
    "resolve_registry_route",
    "split_endpoint_parts",
    "validate_stream_args",
]


def split_endpoint_parts(name: str) -> tuple[str, str, list[str]]:
    """Split a client endpoint attribute name into lowercased resource and hyphenated action segments.

    Returns:
        tuple[str, str, list[str]]: ``(name_lower, resource_lower, action_parts)``.
    """
    name_lower = name.lower()
    parts = name.split("_")
    resource_lower = parts[0].lower()
    action_parts = [resource_lower]
    if len(parts) > 1:
        for part in parts[1:]:
            dashed = "".join("-" + c.lower() if c.isupper() else c for c in part)
            action_parts.append(dashed.lstrip("-"))
    return name_lower, resource_lower, action_parts


def external_stacklevel(package_root: str = "mailjet_rest") -> int:
    """Walk the call stack to point deprecation warnings at the external caller frame.

    Returns:
        int: Stack depth suitable for ``warnings.warn(..., stacklevel=...)``.
    """
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


def emit_deprecation_if_needed(name_lower: str, resource_lower: str) -> None:
    """Emit a non-breaking DeprecationWarning when a legacy endpoint is invoked."""
    target = name_lower if name_lower in DEPRECATION_ADVISORY else resource_lower
    if target in DEPRECATION_ADVISORY:
        replacement = DEPRECATION_ADVISORY[target]
        warnings.warn(
            f"Endpoint '{target}' is deprecated in the Mailjet API. Migrate to '{replacement}'.",
            DeprecationWarning,
            stacklevel=external_stacklevel(),
        )


def resolve_registry_route(
    name: str,
    base_url: str,
    version: str,
    id_val: ResourceId | None,
    action_id: ResourceId | None,
) -> tuple[str, ResourceId | None, ResourceId | None]:
    """Resolve an endpoint URL using the static ``ROUTE_MAP`` registry.

    Returns:
        tuple[str, ResourceId | None, ResourceId | None]: Resolved URL and unconsumed IDs.
    """
    route = ROUTE_MAP[name]
    if route.version is not None:
        version = route.version

    path = route.path
    format_kwargs: dict[str, str] = {}

    if "{id}" in path:  # ruff: ignore[missing-f-string-syntax]
        if id_val is None:
            msg = f"Endpoint '{name}' requires an 'id' parameter."
            raise ValueError(msg)
        format_kwargs["id"] = SecurityGuard.sanitize_segment(id_val)
        id_val = None

    if "{action_id}" in path:  # ruff: ignore[missing-f-string-syntax]
        if action_id is None:
            msg = f"Endpoint '{name}' requires an 'action_id' parameter."
            raise ValueError(msg)
        format_kwargs["action_id"] = SecurityGuard.sanitize_segment(action_id)
        action_id = None

    if format_kwargs:
        path = path.format(**format_kwargs)

    return f"{base_url}/{version}/{path}", id_val, action_id


def _resolve_csv_data_route(
    name_lower: str,
    action_parts: list[str],
    base_url: str,
    version: str,
    id_val: ResourceId | None,
    action_id: ResourceId | None,
) -> tuple[str, ResourceId | None, ResourceId | None]:
    safe_part = SecurityGuard.sanitize_segment(action_parts[0])
    url = f"{base_url}/{version}/DATA/{safe_part}"
    if id_val is not None:
        suffix = "CSVData/text:plain" if name_lower.endswith("_csvdata") else "CSVError/text:csv"
        url += f"/{SecurityGuard.sanitize_segment(id_val)}/{suffix}"
        id_val = None
    if action_id is not None:
        action_id = SecurityGuard.sanitize_segment(action_id)
    return url, id_val, action_id


def resolve_dynamic_route(
    name_lower: str,
    resource_lower: str,
    action_parts: list[str],
    base_url: str,
    version: str,
    id_val: ResourceId | None,
    action_id: ResourceId | None,
) -> tuple[str, ResourceId | None, ResourceId | None]:
    """Resolve an endpoint URL using dynamic legacy attribute naming rules.

    Returns:
        tuple[str, ResourceId | None, ResourceId | None]: Resolved URL and unconsumed IDs.
    """
    if name_lower == "send":
        return f"{base_url}/{version}/send", id_val, action_id

    if name_lower.endswith(("_csvdata", "_csverror")):
        return _resolve_csv_data_route(name_lower, action_parts, base_url, version, id_val, action_id)

    if name_lower.startswith("data_"):
        safe_path = "/".join(SecurityGuard.sanitize_segment(p) for p in action_parts[1:])
        url = f"{base_url}/{version}/data/{safe_path}"
        return url, id_val, SecurityGuard.sanitize_segment(action_id) if action_id is not None else None

    safe_resource = SecurityGuard.sanitize_segment(resource_lower)
    url = f"{base_url}/{version}/REST/{safe_resource}"
    if len(action_parts) > 1:
        safe_action = "/".join(SecurityGuard.sanitize_segment(p) for p in action_parts[1:])
        if id_val is None:
            id_val, action_id = action_id, safe_action
        elif action_id is not None:
            action_id = f"{safe_action}/{SecurityGuard.sanitize_segment(action_id)}"
        else:
            action_id = safe_action
    return url, id_val, action_id


def _append_trailing_segments(
    url: str,
    name: str,
    action_parts: list[str],
    id_val: ResourceId | None,
    action_id: ResourceId | None,
) -> str:
    if id_val is not None:
        url = f"{url}/{SecurityGuard.sanitize_segment(id_val)}"
    if action_id is not None:
        if name in ROUTE_MAP or len(action_parts) == 1:
            url = f"{url}/{SecurityGuard.sanitize_segment(action_id)}"
        else:
            url = f"{url}/{action_id}"
    return url


def build_endpoint_url(
    name: str,
    name_lower: str,
    resource_lower: str,
    action_parts: list[str],
    api_url: str,
    raw_version: str,
    id_val: ResourceId | None = None,
    action_id: ResourceId | None = None,
    *,
    check_deprecation: bool = True,
) -> str:
    """Construct and sanitize a full Mailjet endpoint URL.

    Returns:
        str: Sanitized destination endpoint URL.
    """
    if check_deprecation:
        emit_deprecation_if_needed(name_lower, resource_lower)
    version = raw_version if raw_version in {"v1", "v3", "v3.1", "v4"} else SecurityGuard.sanitize_segment(raw_version)

    if version == "v3" and name_lower == "templates":
        warnings.warn(
            "Mailjet API Ambiguity: Email API (v3) uses singular '/template'",
            DeprecationWarning,
            stacklevel=external_stacklevel(),
        )

    base_url = api_url.rstrip("/")
    if name in ROUTE_MAP:
        url, id_val, action_id = resolve_registry_route(name, base_url, version, id_val, action_id)
    else:
        url, id_val, action_id = resolve_dynamic_route(
            name_lower,
            resource_lower,
            action_parts,
            base_url,
            version,
            id_val,
            action_id,
        )

    return _append_trailing_segments(url, name, action_parts, id_val, action_id)


def build_endpoint_headers(name_lower: str, custom_headers: HeadersMapping | None = None) -> RequestHeaders:
    """Compose default endpoint Content-Type headers merged with sanitized overrides.

    Returns:
        RequestHeaders: Clean headers ready for client request preparation.
    """
    if name_lower.endswith("_csvdata"):
        base_headers = _TEXT_HEADERS
    elif name_lower.endswith("_csverror"):
        base_headers = _CSV_HEADERS
    else:
        base_headers = _JSON_HEADERS
    if custom_headers:
        clean_custom = SecurityGuard.sanitize_headers(dict(custom_headers))
        if any(k.lower() == "content-type" for k in clean_custom):
            filtered_base = {k: v for k, v in base_headers.items() if k.lower() != "content-type"}
            return {**filtered_base, **clean_custom}
        return {**base_headers, **clean_custom}
    return dict(base_headers)


def cast_query_param(orig_ref: Any, raw_values: Any) -> Any:
    """Cast query parameter values to match a reference scalar or collection type.

    Returns:
        Any: Converted query parameter value.
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
    if converter := converters.get(type(orig_ref)):
        return converter()

    return first_val if len(vals) == 1 else vals


def normalize_stream_filters(filters: QueryFilters | None, chunk_size: int) -> tuple[dict[str, Any], int]:
    """Normalize pagination filter keys and validate initial offset for ``stream()``.

    Returns:
        tuple[dict[str, Any], int]: Sanitized filter mapping and validated starting offset.
    """
    current_filters = dict(filters) if filters else {}
    raw_offset = current_filters.pop("offset", None)
    if raw_offset is None:
        raw_offset = current_filters.get("Offset")

    try:
        current_offset: int = cast_query_param(0, raw_offset) if raw_offset is not None else 0
    except (ValueError, TypeError) as e:
        msg = f"stream() Offset filter must be an integer, got: {raw_offset!r}"
        raise ValueError(msg) from e

    if current_offset < 0:
        msg = f"stream() Offset filter must be a non-negative integer, got: {current_offset}"
        raise ValueError(msg)

    current_filters.pop("limit", None)
    current_filters.pop("Limit", None)
    current_filters["Limit"] = chunk_size
    return current_filters, current_offset


def _require_valid_int(value: Any, err_msg: str, *, allow_zero: bool = False) -> None:
    min_val = 0 if allow_zero else 1
    if isinstance(value, bool) or not isinstance(value, int) or value < min_val:
        raise ValueError(err_msg)


def validate_stream_args(
    method: HttpMethod,
    chunk_size: int,
    max_items: int | None,
    *,
    max_limit: int = 1000,
) -> None:
    """Validate pagination parameters passed to synchronous or asynchronous ``stream()``."""
    if method.upper() != "GET":
        msg = f"stream() is designed for GET requests only, got {method}"
        raise ValueError(msg)

    _require_valid_int(chunk_size, "stream() chunk_size must be a strictly positive integer.")
    if chunk_size > max_limit:
        msg = (
            f"stream() chunk_size ({chunk_size}) exceeds Mailjet's maximum Limit of {max_limit}. "
            f"Set chunk_size <= {max_limit}."
        )
        raise ValueError(msg)

    if max_items is not None:
        _require_valid_int(
            max_items,
            "stream() max_items must be a non-negative integer or None.",
            allow_zero=True,
        )


def parse_stream_page(response: Any) -> list[dict[str, Any]]:
    """Decode and validate a paginated Mailjet API response envelope.

    Returns:
        list[dict[str, Any]]: List of item dictionaries from the ``Data`` envelope field.
    """
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


def prepare_call_payload_and_headers(
    name_lower: str,
    data: PayloadType,
    headers: HeadersMapping | None,
    kwargs: dict[str, Any],
) -> tuple[RequestHeaders, PayloadType]:
    """Handle legacy encoding kwargs and merge custom headers for endpoint requests.

    Returns:
        tuple[RequestHeaders, PayloadType]: Merged request headers and serialized payload.
    """
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
            stacklevel=external_stacklevel(),
        )
        if isinstance(data, (Mapping, list)):
            serializable = dict(data) if isinstance(data, Mapping) and not isinstance(data, dict) else data
            data_str = json.dumps(serializable, ensure_ascii=ensure_ascii if ensure_ascii is not None else True)
            data = data_str.encode(data_encoding) if data_encoding else data_str

    return build_endpoint_headers(name_lower, headers), data
