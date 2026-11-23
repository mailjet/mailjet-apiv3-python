"""Filesystem attachment path traversal and multipart upload security helpers."""

from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Mapping
from pathlib import Path
from typing import TYPE_CHECKING, Any


if TYPE_CHECKING:
    from collections.abc import Callable

    from mailjet_rest.types import HeadersMapping, RequestHeaders


__all__ = ["check_file_size", "validate_attachment_path", "validate_multipart_files"]


def _coerce_attachment_raw_path(file_path: Any) -> tuple[str, Path]:
    raw_os_path: Any = os.fspath(file_path)
    if isinstance(raw_os_path, bytes):
        if b"\x00" in raw_os_path:
            msg = "Security Violation (CWE-22): Null byte detected in attachment path."
            raise ValueError(msg)
        original_str = os.fsdecode(raw_os_path)
    else:
        original_str = str(raw_os_path)
        if "\x00" in original_str:
            msg = "Security Violation (CWE-22): Null byte detected in attachment path."
            raise ValueError(msg)
    return original_str, Path(original_str)


def _validate_zero_trust_path(original_path: str, target: Path) -> None:
    if ".." in original_path:
        msg = "Security Alert (CWE-22): Path traversal tokens ('..') are explicitly forbidden."
        raise ValueError(msg)

    is_in_temp = False
    with contextlib.suppress(Exception):
        import tempfile  # ruff: ignore[import-outside-top-level]

        temp_dir = Path(tempfile.gettempdir()).resolve()
        is_in_temp = target.is_relative_to(temp_dir)

    if is_in_temp:
        return

    forbidden_roots = ("/etc", "/var", "/root", "/boot", "C:\\Windows", "C:\\System32")
    path_str = str(target).lower()
    if any(path_str.startswith(root.lower()) for root in forbidden_roots):
        msg = "Security Alert: Access to sensitive OS system directories is explicitly forbidden."
        raise ValueError(msg)

    forbidden_components = {"etc", "sys", "proc", "dev", "windows", "system32", "root", "boot"}
    if any(part.lower() in forbidden_components for part in target.parts):
        msg = "Security Alert: Access to sensitive OS system directories is explicitly forbidden."
        raise ValueError(msg)


def validate_attachment_path(file_path: Path | str, safe_base_dir: Path | str | None = None) -> Path:
    """Prevent path traversal (CWE-22) via strict symlink and boundary resolution.

    Returns:
        Path: Resolved and validated filesystem path.
    """
    original_path, raw_path = _coerce_attachment_raw_path(file_path)

    try:
        if raw_path.is_symlink():
            sys.audit("mailjet.security.path_traversal", original_path)
            msg = "Security Violation (CWE-22): Symlinks are strictly forbidden for attachments."
            raise ValueError(msg)
        target = raw_path.resolve()
    except (OSError, RuntimeError) as e:
        msg = f"Security Violation (CWE-22): Invalid attachment path '{original_path}'."
        raise ValueError(msg) from e

    if safe_base_dir is not None:
        base = Path(safe_base_dir).resolve()
        if not target.is_relative_to(base):
            sys.audit("mailjet.security.path_traversal", str(target))
            msg = f"Security Violation: Traversal detected. '{target}' is outside '{base}'."
            raise ValueError(msg)
    else:
        _validate_zero_trust_path(original_path, target)

    try:
        exists_and_file = target.exists() and target.is_file()
    except OSError as e:
        msg = f"Security Violation (CWE-22): Cannot inspect attachment path '{target}'."
        raise ValueError(msg) from e

    if not exists_and_file:
        msg = f"Attachment not found or is not a file: {target}"
        raise FileNotFoundError(msg)

    return target


def check_file_size(path: Path, max_size_bytes: int = 15 * 1024 * 1024) -> None:
    """Prevent resource exhaustion (CWE-400) by capping attachment file size."""
    target = Path(path)
    if not target.is_file():
        msg = f"Security Alert (CWE-400): Path is not a regular file: {target}"
        raise ValueError(msg)

    size = target.stat().st_size
    if size > max_size_bytes:
        msg = f"Security Violation: File '{target.name}' exceeds safe threshold."
        raise ValueError(msg)


def _validate_multipart_text(label: str, value: Any) -> None:
    if isinstance(value, str):
        text = value
    elif isinstance(value, (bytes, bytearray)):
        text = bytes(value).decode("latin-1")
    else:
        return
    if "\r" in text or "\n" in text or "\x00" in text:
        sys.audit("mailjet.security.header_injection", label)
        msg = f"Security Violation: Multipart file {label} contains forbidden CRLF or NUL characters."
        raise ValueError(msg)


def _validate_multipart_spec(
    file_spec: Any,
    *,
    header_sanitizer: Callable[[HeadersMapping], RequestHeaders],
) -> None:
    if not isinstance(file_spec, (tuple, list)):
        return
    if len(file_spec) >= 1 and file_spec[0] is not None:
        _validate_multipart_text("filename", file_spec[0])
    if len(file_spec) >= 3 and file_spec[2] is not None:
        _validate_multipart_text("content_type", file_spec[2])
    if len(file_spec) >= 4 and isinstance(file_spec[3], Mapping):
        header_sanitizer(file_spec[3])


def _validate_multipart_entry(
    entry: Any,
    *,
    header_sanitizer: Callable[[HeadersMapping], RequestHeaders],
) -> None:
    if not isinstance(entry, tuple) or len(entry) != 2:
        return
    field_name, file_spec = entry
    _validate_multipart_text("field_name", field_name)
    _validate_multipart_spec(file_spec, header_sanitizer=header_sanitizer)


def validate_multipart_files(
    files: Any,
    *,
    header_sanitizer: Callable[[HeadersMapping], RequestHeaders],
) -> None:
    """Validate multipart upload metadata against CRLF and NUL smuggling (CWE-93, CWE-434)."""
    if isinstance(files, Mapping):
        items: Any = files.items()
    elif isinstance(files, (list, tuple)):
        items = files
    else:
        return

    for entry in items:
        _validate_multipart_entry(entry, header_sanitizer=header_sanitizer)
