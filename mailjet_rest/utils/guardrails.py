"""Utility module providing security and routing guardrails for the Mailjet SDK.

This module acts as the centralized ingress/egress validation layer, implementing
Defense-in-Depth against OWASP Top 10 vulnerabilities including CWE-22 (Path Traversal),
CWE-918 (SSRF), CWE-400 (Resource Exhaustion), and CWE-117 (Log Forging).
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import logging
import math
import re
import sys
import traceback
import unicodedata
import warnings
from collections.abc import Mapping
from functools import lru_cache
from typing import TYPE_CHECKING, Any, ClassVar, Final
from urllib.parse import quote, unquote, urlparse

from mailjet_rest.utils.filesystem_security import (
    check_file_size as _check_file_size,
    validate_attachment_path as _validate_attachment_path,
    validate_multipart_files as _validate_multipart_files,
)
from mailjet_rest.utils.html_guard import (
    XSS_PATTERN as _XSS_PATTERN,
    LazyHtmlGuardMeta as _LazyGuardMeta,
    analyze_html_safety as _analyze_html_safety,
)
from mailjet_rest.utils.transport_security import (
    SecretAuth,
    SecureHTTPAdapter,
    _build_tls_context,
    get_secure_ssl_context,
    resolve_tls_verify,
)


if TYPE_CHECKING:
    from html.parser import HTMLParser
    from pathlib import Path

    from mailjet_rest.types import (
        AuthCredentials,
        HeadersMapping,
        RequestHeaders,
        SendV31Payload,
        TimeoutType,
    )

try:
    import orjson as _orjson_mod
except ImportError:  # pragma: no cover - optional speedup extra
    _orjson_mod = None
_orjson: Any = _orjson_mod


if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


__all__ = [
    "RedactingFilter",
    "SecretAuth",
    "SecureHTTPAdapter",
    "SecurityGuard",
    "_build_tls_context",
    "get_secure_ssl_context",
]


_CRLF_RE: Final = re.compile(r"[\r\n]")
# RFC 9110 strict control characters (blocks all non-printable ASCII except \x09 tab)
_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_PATH_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x1f\x7f]")
_ASCII_DOMAIN_RE: Final = re.compile(r"^[A-Za-z0-9_-]{1,63}(?:\.[A-Za-z0-9_-]{1,63})*$")
_MAX_DNS_DOMAIN_LEN: Final = 253
_MAX_DNS_LABEL_LEN: Final = 63


@lru_cache(maxsize=1)
def _get_secret_pattern() -> re.Pattern[str]:
    """Lazy-compile strict patterns to minimize cold-boot overhead.

    ReDoS prevented by eliminating overlapping quantifiers (+)
    and enforcing strict finite bounds ({1,10} and {1,200}).

    Returns:
        re.Pattern[str]: The compiled regex pattern for detecting secrets.
    """
    return re.compile(
        r"(?i)(Authorization|api[_-]key|api[_-]secret|token)((?:\s*[:='\"\]]+\s*|\s+)(?:(?:Bearer|Basic|Token)\s+)?)([^\s'\"\}\]]{1,200})"
    )


_SECRET_SENTINELS: Final[tuple[str, ...]] = (
    "authorization",
    "api_key",
    "api-key",
    "api_secret",
    "api-secret",
    "token",
)


def _may_contain_secret(text: str) -> bool:
    lower = text.lower()
    return any(token in lower for token in _SECRET_SENTINELS)


class RedactingFilter(logging.Filter):
    """Deep recursive logging filter to automatically scrub API keys and secrets (CWE-117, CWE-316)."""

    MAX_REDACTION_DEPTH: Final[int] = 4

    _SENSITIVE_KEY_NAMES: Final[frozenset[str]] = frozenset(
        {
            "password",
            "passwd",
            "pwd",
            "secret",
            "api_secret",
            "api-secret",
            "api_key",
            "api-key",
            "apikey",
            "token",
            "access_token",
            "refresh_token",
            "authorization",
            "cookie",
            "set-cookie",
            "private_key",
        }
    )

    # Standard LogRecord attributes to ignore for maximum performance
    _STANDARD_ATTRS: Final[frozenset[str]] = frozenset(
        {
            "args",
            "asctime",
            "created",
            "exc_info",
            "exc_text",
            "filename",
            "funcName",
            "levelname",
            "levelno",
            "lineno",
            "message",
            "module",
            "msecs",
            "msg",
            "name",
            "pathname",
            "process",
            "processName",
            "relativeCreated",
            "stack_info",
            "thread",
            "threadName",
            "taskName",
        }
    )

    @classmethod
    def _is_sensitive_key(cls, key: object, value: object) -> bool:
        return (
            isinstance(key, str)
            and key.strip().lower() in cls._SENSITIVE_KEY_NAMES
            and value is not None
            and not isinstance(value, bool)
        )

    @staticmethod
    def _redact_str(data: str) -> str:
        try:
            return _get_secret_pattern().sub(r"\1\2********", data)
        except Exception:  # ruff: ignore[blind-except]
            return "[REDACTION_FAILED_UNSAFE_STRING]"

    @classmethod
    def _redact_str_fast(cls, data: str) -> str:
        if not _may_contain_secret(data):
            return data
        return cls._redact_str(data)

    def _redact_tuple(self, data: tuple[Any, ...], depth: int) -> tuple[Any, ...]:
        """Recursively sanitize tuple items preserving namedtuple structure.

        Returns:
            The sanitized tuple or NamedTuple instance.
        """
        if hasattr(data, "_fields"):  # Preserves typing.NamedTuple
            with contextlib.suppress(Exception):
                return type(data)(*(self._deep_redact(item, depth + 1) for item in data))
        return tuple(self._deep_redact(item, depth + 1) for item in data)

    def _redact_object(self, data: Any, depth: int) -> Any:
        """Recursively sanitize custom objects, dataclasses, and Pydantic models.

        Returns:
            The sanitized dictionary, string, or primitive representation.
        """
        if hasattr(data, "model_dump") and callable(data.model_dump):
            with contextlib.suppress(Exception):
                return self._deep_redact(data.model_dump(), depth + 1)

        if hasattr(data, "__dict__"):
            with contextlib.suppress(Exception):
                return self._deep_redact(vars(data), depth + 1)

        try:
            str_val = str(data)
        except Exception:  # ruff: ignore[blind-except]
            return ""

        return self._redact_str_fast(str_val)

    def _redact_collection(self, data: Any, depth: int) -> Any:
        if isinstance(data, dict):
            return {
                k: ("********" if self._is_sensitive_key(k, v) else self._deep_redact(v, depth + 1))
                for k, v in data.items()
            }
        if isinstance(data, list):
            return [self._deep_redact(item, depth + 1) for item in data]
        if isinstance(data, tuple):
            return self._redact_tuple(data, depth)
        if isinstance(data, set):
            return {self._deep_redact(item, depth + 1) for item in data}
        if isinstance(data, frozenset):
            return frozenset(self._deep_redact(item, depth + 1) for item in data)
        return self._redact_object(data, depth)

    def _deep_redact(self, data: Any, depth: int = 0) -> Any:
        """Recursively search and scrub secrets from complex nested data structures.

        Returns:
            The fully sanitized data structure representation.
        """
        if depth > self.MAX_REDACTION_DEPTH:
            return "[MAX_DEPTH_REACHED]"
        if isinstance(data, (int, float, bool, type(None))):
            return data
        if isinstance(data, str):
            return self._redact_str_fast(data)
        return self._redact_collection(data, depth)

    def _redact_exc_info(self, record: logging.LogRecord) -> None:
        if isinstance(record.exc_text, str):
            record.exc_text = self._redact_str_fast(record.exc_text)

        if isinstance(record.exc_info, tuple) and len(record.exc_info) == 3:
            formatted = "".join(traceback.format_exception(*record.exc_info)).rstrip("\n")
            record.exc_text = self._redact_str_fast(formatted)
            record.exc_info = None

    def _redact_extra_attrs(self, record: logging.LogRecord) -> None:
        for attr_name, attr_value in list(record.__dict__.items()):
            if attr_name not in self._STANDARD_ATTRS:
                if self._is_sensitive_key(attr_name, attr_value):
                    record.__dict__[attr_name] = "********"
                else:
                    record.__dict__[attr_name] = self._deep_redact(attr_value)

    def _redact_msg_and_collect_flags(self, record: logging.LogRecord) -> tuple[bool, bool, bool] | None:
        has_args = bool(isinstance(record.args, (dict, tuple)) and record.args)
        has_exc = record.exc_text is not None or record.exc_info is not None
        has_extras = any(attr not in self._STANDARD_ATTRS for attr in record.__dict__)

        if isinstance(record.msg, str) and _may_contain_secret(record.msg):
            record.msg = self._redact_str(record.msg)
        elif not has_args and not has_exc and not has_extras:
            return None
        return has_args, has_extras, has_exc

    def _scrub_record(self, record: logging.LogRecord) -> None:
        flags = self._redact_msg_and_collect_flags(record)
        if flags is None:
            return
        has_args, has_extras, has_exc = flags
        if has_args:
            record.args = self._deep_redact(record.args)
        if has_extras:
            self._redact_extra_attrs(record)
        if has_exc:
            self._redact_exc_info(record)

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out sensitive secrets from log records safely.

        Returns:
            bool: Always True (permits the log to write but strictly scrubs the content beforehand).
        """
        try:
            self._scrub_record(record)
        except Exception as e:  # ruff: ignore[blind-except]
            # Failsafe: Never let logging filters crash application execution
            logging.getLogger(__name__).debug("Redaction filter failed: %s", e)
        return True


def _validate_url_hostname(parsed: Any, allowed_root_domain: str) -> None:
    hostname = parsed.hostname or ""
    if "%" in hostname:
        msg = (
            f"Security Alert (CWE-918): Hostname '{hostname}' is not permitted. "
            f"Must be a '{allowed_root_domain}' domain or a local loopback for testing."
        )
        raise ValueError(msg)

    allowed_exact_hosts = frozenset(
        {
            allowed_root_domain,
            f"api.{allowed_root_domain}",
            "localhost",
            "127.0.0.1",
            "::1",
        }
    )
    if hostname not in allowed_exact_hosts and not hostname.endswith(f".{allowed_root_domain}"):
        msg = (
            f"Security Alert (CWE-918): Hostname '{hostname}' is not permitted. "
            f"Must be a '{allowed_root_domain}' domain or a local loopback for testing."
        )
        raise ValueError(msg)


def _validate_url_uncached(url: str, allowed_root_domain: str) -> None:
    if not isinstance(url, str) or not url.strip():
        msg = "Security Alert (CWE-918): API URL must be a non-empty string."
        raise ValueError(msg)
    if _PATH_CONTROL_CHAR_RE.search(url):
        msg = "Security Alert (CWE-918): URL contains forbidden control characters."
        raise ValueError(msg)

    parsed = urlparse(url)
    if "#" in url or parsed.fragment:
        msg = "Security Alert (CWE-918): URL fragments ('#') are forbidden."
        raise ValueError(msg)
    if parsed.scheme not in {"http", "https"}:
        msg = f"Security Alert (CWE-918): Invalid scheme '{parsed.scheme}'. Only http/https allowed."
        raise ValueError(msg)
    if parsed.username is not None or parsed.password is not None:
        msg = "Security Alert (CWE-918): Embedded credentials in API URL are forbidden."
        raise ValueError(msg)

    _validate_url_hostname(parsed, allowed_root_domain)


@lru_cache(maxsize=32)
def _validate_config_url_cached(url: str, allowed_root_domain: str) -> None:
    _validate_url_uncached(url, allowed_root_domain)
    if "?" in url or "#" in url:
        msg = "Security Alert (CWE-918): Base API URL must not contain query strings or fragments."
        raise ValueError(msg)


def _deep_strip_volatile(
    data: Any,
    volatile_keys: frozenset[str],
    depth: int = 0,
    seen: set[int] | None = None,
) -> Any:
    if seen is None:
        seen = set()

    obj_id = id(data)
    # Active Cycle Detection (CWE-674) to prevent RecursionError crashes
    if obj_id in seen:
        return "[Circular]"

    if depth > 50:
        msg = "Security Violation: Payload exceeds maximum safe nesting depth."
        raise ValueError(msg)

    if isinstance(data, Mapping):
        seen.add(obj_id)
        try:
            return {
                k: _deep_strip_volatile(v, volatile_keys, depth + 1, seen)
                for k, v in data.items()
                if k not in volatile_keys
            }
        finally:
            seen.discard(obj_id)
    if isinstance(data, (list, tuple, set)):
        seen.add(obj_id)
        try:
            return [_deep_strip_volatile(item, volatile_keys, depth + 1, seen) for item in data]
        finally:
            seen.discard(obj_id)
    return data


class SecurityGuard(metaclass=_LazyGuardMeta):
    """Centralized OWASP API security and payload guardrails."""

    __slots__ = ()

    MAX_HTML_SIZE: int = 5 * 1024 * 1024  # 5MB safe limit (CWE-400)
    MAX_TAG_COUNT: int = 10000  # DoS protection against tag bombs (CWE-400)

    VOLATILE_IDEMPOTENCY_KEYS: ClassVar[frozenset[str]] = frozenset({"CustomID", "EventPayload"})
    ALLOWED_KWARGS: ClassVar[frozenset[str]] = frozenset(
        {"proxies", "cert", "stream", "verify", "allow_redirects", "files"}
    )

    if TYPE_CHECKING:

        class _SpamGuardParser(HTMLParser):
            has_script: bool
            is_safe: bool
            issues: list[str]
            tag_count: int
            max_tags: int

            def __init__(self, max_tags: int = 10000) -> None:
                """Initialize the HTML safety parser stub."""
                super().__init__()
                self.max_tags = max_tags

    @staticmethod
    def resolve_tls_verify(verify: Any) -> bool | str:
        """Validate TLS verification flag or custom CA bundle path (CWE-295).

        Returns:
            bool | str: True for system/certifi CA verification, or validated CA bundle path string.
        """
        return resolve_tls_verify(verify)

    @staticmethod
    def enable_audit_logging() -> None:
        """Enable runtime audit logging (e.g. via sys.audit for PEP 578)."""
        sys.audit("mailjet.security.audit_enabled")

    @staticmethod
    def filter_safe_kwargs(kwargs: dict[str, Any]) -> dict[str, Any]:
        """Prevent Mass Assignment of internal HTTP client states (CWE-915).

        Args:
            kwargs: Dictionary of keyword arguments passed to the network layer.

        Returns:
            A filtered dictionary containing only allowed low-level HTTP settings.
        """
        return {k: v for k, v in kwargs.items() if k in SecurityGuard.ALLOWED_KWARGS}

    @staticmethod
    def validate_config_url(url: str, allowed_root_domain: str = "mailjet.com") -> None:
        """Prevent SSRF by strictly validating the base API URL.

        Args:
            url (str): The configured API URL to validate.
            allowed_root_domain (str): The trusted root domain for production traffic.
        """
        _validate_config_url_cached(url, allowed_root_domain)

    @staticmethod
    def _validate_fast_target_prefix(url: str) -> None:
        if "#" in url:
            msg = "Security Alert (CWE-918): URL fragments ('#') are forbidden."
            raise ValueError(msg)
        if not (url.isascii() and url.isprintable()) and _PATH_CONTROL_CHAR_RE.search(url):
            msg = "Security Alert (CWE-918): URL contains forbidden control characters."
            raise ValueError(msg)

    @staticmethod
    def validate_target_url(
        url: str,
        *,
        base_api_url: str | None = None,
        allowed_root_domain: str = "mailjet.com",
    ) -> None:
        """Validate a per-request target URL against SSRF with O(1) prefix fast-path."""
        if isinstance(base_api_url, str) and base_api_url:
            _validate_config_url_cached(base_api_url, allowed_root_domain)
            prefix = base_api_url if base_api_url.endswith("/") else f"{base_api_url}/"
            if isinstance(url, str) and url.startswith(prefix):
                SecurityGuard._validate_fast_target_prefix(url)
                return
        _validate_url_uncached(url, allowed_root_domain)

    @staticmethod
    def _validate_proxy_entry(proxy_val: Any) -> bool:
        if not isinstance(proxy_val, str):
            msg = f"Invalid proxy URL type: expected str, got {type(proxy_val).__name__}."
            raise TypeError(msg)
        if _CRLF_RE.search(proxy_val) or _PATH_CONTROL_CHAR_RE.search(proxy_val):
            msg = "Security Violation: Proxy URL contains forbidden control characters."
            raise ValueError(msg)
        if "://" in proxy_val:
            parsed = urlparse(proxy_val)
            scheme = parsed.scheme.lower()
            if scheme not in {"http", "https", "socks5", "socks5h"} or not parsed.hostname:
                msg = f"Security Alert (CWE-918): Invalid or unsupported proxy scheme '{scheme}'."
                raise ValueError(msg)
            return scheme == "http"
        return proxy_val.lower().startswith("http://")

    @staticmethod
    def check_request_security(kwargs: dict[str, Any]) -> None:
        """Validate proxy configuration and warn on unencrypted HTTP proxies."""
        proxies = kwargs.get("proxies")
        if proxies is None:
            return
        if isinstance(proxies, str):
            candidates: list[Any] = [proxies]
        elif isinstance(proxies, Mapping):
            candidates = [p for p in proxies.values() if p is not None]
        else:
            msg = f"Invalid 'proxies' type: expected str, Mapping, or None, got {type(proxies).__name__}."
            raise TypeError(msg)

        has_http_proxy = False
        for candidate in candidates:
            if SecurityGuard._validate_proxy_entry(candidate):
                has_http_proxy = True
        if has_http_proxy:
            warnings.warn("Security Warning: Unencrypted HTTP proxy detected.", UserWarning, stacklevel=3)

    @staticmethod
    def _has_forbidden_header_chars(value: str) -> bool:
        return bool(
            _CRLF_RE.search(value)
            or _CONTROL_CHAR_RE.search(value)
            or any(unicodedata.category(c) == "Cc" and c != "\t" for c in value)
        )

    @staticmethod
    def _assert_header_safe_chars(header_name: str, text: str) -> None:
        if not (text.isascii() and text.isprintable()) and SecurityGuard._has_forbidden_header_chars(text):
            sys.audit("mailjet.security.header_injection", header_name)
            msg = f"Security Violation: CRLF injection detected in header '{header_name}'"
            raise ValueError(msg)

    @staticmethod
    def _validate_header_entry(k: Any, v: Any) -> None:
        if not isinstance(k, str):
            msg = f"Invalid header name type: expected str, got {type(k).__name__}."
            raise TypeError(msg)
        if v is not None and not isinstance(v, str):
            msg = f"Invalid header value type for '{k}': expected str or None, got {type(v).__name__}."
            raise TypeError(msg)
        SecurityGuard._assert_header_safe_chars(k, k)
        if v is not None:
            SecurityGuard._assert_header_safe_chars(k, v)

    @staticmethod
    def sanitize_headers(headers: HeadersMapping) -> RequestHeaders:
        """Prevent HTTP Header Injection (CWE-113).

        Returns:
            RequestHeaders: The sanitized headers safely screened for CRLF and control-byte injections.
        """
        clean_headers: RequestHeaders = {}
        for k, v in headers.items():
            SecurityGuard._validate_header_entry(k, v)
            clean_headers[k] = v
        return clean_headers

    @staticmethod
    def validate_multipart_files(files: Any) -> None:
        """Validate multipart upload metadata against CRLF and NUL smuggling (CWE-93, CWE-434)."""
        _validate_multipart_files(files, header_sanitizer=SecurityGuard.sanitize_headers)

    @staticmethod
    def check_control_characters(field_name: str, value: Any) -> None:
        """Strictly prevent all unprintable ASCII Control Characters (CWE-20)."""
        if isinstance(value, str) and _CONTROL_CHAR_RE.search(value):
            sys.audit("mailjet.security.control_characters", field_name)
            msg = f"Security Violation: Unprintable control character detected in '{field_name}'"
            raise ValueError(msg)

    @staticmethod
    def analyze_html_safety(html_content: str) -> dict[str, Any]:
        """SpamGuard: Analyzes HTML payloads for XSS triggers and poor deliverability markers.

        Returns:
            dict[str, Any]: The analysis report containing boolean 'is_safe' and any
            'issues' strings.
        """

        def _make_parser() -> Any:
            return SecurityGuard._SpamGuardParser()

        return _analyze_html_safety(
            html_content,
            parser_factory=_make_parser,
            max_html_size=SecurityGuard.MAX_HTML_SIZE,
            max_tag_count=SecurityGuard.MAX_TAG_COUNT,
        )

    @staticmethod
    def _canonical_json_bytes(safe_payload: Any) -> bytes:
        if _orjson is not None:
            try:
                raw: bytes = _orjson.dumps(safe_payload, option=_orjson.OPT_SORT_KEYS, default=str)
            except TypeError:
                # Fall back to stdlib json.dumps when orjson rejects non-str keys.
                pass
            else:
                return raw
        return json.dumps(safe_payload, sort_keys=True, separators=(",", ":"), default=str).encode("utf-8")

    @staticmethod
    def generate_payload_fingerprint(payload: Mapping[str, Any] | dict[str, Any] | SendV31Payload | list[Any]) -> str:
        """Generates a safe SHA-256 Idempotency hash for the exact JSON payload.

        Returns:
            str: The generated SHA-256 hash.
        """
        try:
            safe_payload = _deep_strip_volatile(payload, SecurityGuard.VOLATILE_IDEMPOTENCY_KEYS)
            serialized_bytes = SecurityGuard._canonical_json_bytes(safe_payload)
            return hashlib.sha256(serialized_bytes).hexdigest()
        except Exception as e:
            msg = "Payload hashing failed due to malformed or deeply nested structure."
            raise ValueError(msg) from e

    @staticmethod
    def validate_attachment_path(file_path: Path | str, safe_base_dir: Path | str | None = None) -> Path:
        """Prevent Path Traversal (CWE-22) via strict resolution, symlink, and boundary checks.

        Falls back to Zero-Trust OS directory restrictions if no safe_base_dir is supplied.

        Returns:
            Path: The resolved and strictly validated pathlib.Path object.
        """
        return _validate_attachment_path(file_path, safe_base_dir=safe_base_dir)

    @staticmethod
    def check_file_size(path: Path, max_size_bytes: int = 15 * 1024 * 1024) -> None:
        """Prevent Resource Exhaustion (CWE-400). Limit defaults to 15MB."""
        _check_file_size(path, max_size_bytes=max_size_bytes)

    @staticmethod
    def _validate_scalar_timeout(timeout: Any) -> float:
        """Helper to validate a single scalar timeout value (CWE-400).

        Args:
            timeout (Any): The timeout value to validate.

        Returns:
            float: The validated scalar timeout in seconds.
        """
        # Explicitly check for bool to prevent True/False coercing to 1.0/0.0
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            msg = f"Timeout must be a numeric float or int, got {type(timeout).__name__}."
            raise TypeError(msg)

        try:
            timeout_val = float(timeout)
        except OverflowError as e:
            msg = f"Timeout value is out of range or invalid: {e}"
            raise ValueError(msg) from e

        if math.isinf(timeout_val) or math.isnan(timeout_val):
            sys.audit("mailjet.security.resource_exhaustion", str(timeout))
            msg = f"Security Violation: Timeout cannot be Infinity or NaN. Got: {timeout}"
            raise ValueError(msg)

        if timeout_val <= 0:
            msg = f"Timeout must be a strictly positive finite number, got {timeout}."
            raise ValueError(msg)

        max_timeout = 86400.0  # 24 hours max
        if timeout_val > max_timeout:
            msg = f"Timeout exceeds maximum allowed limit of {max_timeout} seconds."
            raise ValueError(msg)

        return timeout_val

    @staticmethod
    def validate_timeout(
        timeout: TimeoutType,
    ) -> int | float | tuple[float, float] | None:
        """Validate and normalize scalar or tuple timeouts (CWE-400).

        Returns:
            int | float | tuple[float, float] | None: Sanitized timeout configuration.
        """
        if timeout is None:
            warnings.warn(
                "Timeout set to None allows infinite socket blocking (CWE-400).",
                DeprecationWarning,
                stacklevel=2,
            )
            return None

        if isinstance(timeout, tuple):
            if len(timeout) != 2:
                msg = "Timeout tuple must contain exactly two elements."  # type: ignore[unreachable]
                raise ValueError(msg)
            connect_timeout = SecurityGuard.validate_timeout(timeout[0])
            read_timeout = SecurityGuard.validate_timeout(timeout[1])
            if not isinstance(connect_timeout, (int, float)) or not isinstance(read_timeout, (int, float)):
                msg = "Timeout tuple elements must be valid numeric values."
                raise TypeError(msg)
            return float(connect_timeout), float(read_timeout)

        try:
            res = SecurityGuard._validate_scalar_timeout(timeout)
        except (OverflowError, ValueError, TypeError) as e:
            if isinstance(e, (ValueError, TypeError)):
                raise
            msg = f"Timeout value is out of range or invalid: {e}"
            raise ValueError(msg) from e
        else:
            return res

    @staticmethod
    def _normalize_domain_part(domain_part: str, raw_input: str, *, is_email: bool) -> str:
        err_prefix = "Invalid IDN in email" if is_email else "Invalid IDN"
        if len(domain_part) <= _MAX_DNS_DOMAIN_LEN and _ASCII_DOMAIN_RE.fullmatch(domain_part):
            return domain_part.lower()
        if len(domain_part) > _MAX_DNS_DOMAIN_LEN or any(
            len(lbl) > _MAX_DNS_LABEL_LEN for lbl in domain_part.split(".")
        ):
            msg = f"{err_prefix}: {raw_input}"
            raise ValueError(msg)
        try:
            return domain_part.encode("idna").decode("ascii")
        except UnicodeError as e:
            msg = f"{err_prefix}: {raw_input}"
            raise ValueError(msg) from e

    @staticmethod
    def normalize_domain(email_or_domain: str) -> str:
        """Prevent Unicode Homograph attacks by encoding IDNs to Punycode (RFC 3490).

        Uses an ASCII fast path with RFC 1035 label bounds before falling back to IDNA.

        Returns:
            str: The fully normalized punycode domain representation.
        """
        if not email_or_domain:
            return email_or_domain

        local_part, sep, domain_part = email_or_domain.rpartition("@")
        if sep:
            puny_domain = SecurityGuard._normalize_domain_part(domain_part, email_or_domain, is_email=True)
            return f"{local_part}@{puny_domain}"

        return SecurityGuard._normalize_domain_part(email_or_domain, email_or_domain, is_email=False)

    @staticmethod
    def _unquote_segment_bounded(raw_str: str) -> str:
        test_decoded = raw_str
        for _ in range(3):
            new_decoded = unquote(test_decoded)
            if new_decoded == test_decoded:
                return unicodedata.normalize("NFKC", test_decoded)
            test_decoded = new_decoded
        msg = "Security Alert (CWE-116): Excessive URL encoding detected."
        raise ValueError(msg)

    @staticmethod
    def _assert_segment_delimiters(raw_str: str, test_decoded: str) -> None:
        if "?" in raw_str or "#" in raw_str or "?" in test_decoded or "#" in test_decoded:
            sys.audit("mailjet.security.path_traversal", test_decoded)
            msg = "Security Alert (CWE-22): Query or fragment delimiters ('?', '#') are forbidden in path segments."
            raise ValueError(msg)
        if ".." in test_decoded or "/" in test_decoded or "\\" in test_decoded:
            sys.audit("mailjet.security.path_traversal", test_decoded)
            msg = "Security Alert (CWE-22): Path traversal attempt."
            raise ValueError(msg)

    @staticmethod
    def _assert_safe_decoded_segment(raw_str: str, test_decoded: str) -> None:
        if _PATH_CONTROL_CHAR_RE.search(test_decoded):
            sys.audit("mailjet.security.control_characters", "path_segment")
            msg = "Security Alert (CWE-20): Forbidden control characters."
            raise ValueError(msg)
        SecurityGuard._assert_segment_delimiters(raw_str, test_decoded)
        if any(marker in test_decoded for marker in ("{{", "}}", "{%")):
            msg = "Security Alert (CWE-94): Template injection attempt."
            raise ValueError(msg)
        if _XSS_PATTERN.search(test_decoded):
            msg = "Security Alert (CWE-79): XSS attempt detected."
            raise ValueError(msg)

    @staticmethod
    def sanitize_segment(segment: Any) -> str:
        """Poka-yoke: Safely encode path segments preventing CWE-22, CWE-116, CWE-128, CWE-94, and CWE-79.

        Returns:
            str: The safely URL-encoded path segment preventing path breakout sequences.
        """
        if segment is None:
            return ""
        if isinstance(segment, (dict, list, set, bool)):
            msg = f"Security Alert: Invalid segment type {type(segment).__name__}."
            raise TypeError(msg)

        raw_str = str(segment)
        test_decoded = SecurityGuard._unquote_segment_bounded(raw_str)
        SecurityGuard._assert_safe_decoded_segment(raw_str, test_decoded)
        return quote(raw_str, safe="").replace(".", "%2E")

    @staticmethod
    def sanitize_log_trace(trace_val: Any) -> str:
        """Prevent Log Forging (CWE-117) by stripping control characters.

        Returns:
            str: The strictly formatted safe tracing suffix stripped of structural tokens.
        """
        if not trace_val:
            return ""

        # Neutralize control characters [\x00-\x1f\x7f] and normalize whitespace
        clean_str = _PATH_CONTROL_CHAR_RE.sub("_", str(trace_val))
        return re.sub(r"\s+", "_", clean_str)

    @staticmethod
    def _validate_token(auth: str) -> str:
        """Validate a Bearer token string.

        Returns:
            str: The validated and stripped token string.
        """
        clean_token = auth.strip()
        if not clean_token:
            msg = "Bearer token cannot be an empty string."
            raise ValueError(msg)
        if _CRLF_RE.search(clean_token) or _CONTROL_CHAR_RE.search(clean_token):
            msg = "Auth credentials contain forbidden control characters."
            raise ValueError(msg)
        if any(ch.isspace() for ch in clean_token) or any(
            unicodedata.category(c) in {"Zs", "Cc", "Cf"} for c in clean_token
        ):
            msg = "Auth credentials contain invalid whitespace or control characters."
            raise ValueError(msg)
        return clean_token

    @staticmethod
    def _validate_auth_part(item: str) -> None:
        if not item or not item.strip():
            msg = "Auth credentials cannot be empty or whitespace-only."
            raise ValueError(msg)
        if _CRLF_RE.search(item) or _CONTROL_CHAR_RE.search(item):
            msg = "Auth credentials contain forbidden control characters."
            raise ValueError(msg)
        if any(unicodedata.category(c) in {"Zs", "Cc", "Cf"} for c in item if c != " "):
            msg = "Auth credentials contain invalid whitespace or control characters."
            raise ValueError(msg)

    @staticmethod
    def _validate_basic_auth(auth: tuple[str, str]) -> SecretAuth:
        """Validate a Basic Auth tuple and return a SecretAuth instance.

        Returns:
            SecretAuth: The validated and wrapped SecretAuth instance.
        """
        if len(auth) != 2:
            msg = "Basic auth tuple must contain exactly two elements: (API_KEY, API_SECRET)."  # type: ignore[unreachable]
            raise ValueError(msg)
        key, secret = auth
        if not isinstance(key, str) or not isinstance(secret, str):
            msg = "Auth tuple elements must be strings."  # type: ignore[unreachable]
            raise TypeError(msg)
        SecurityGuard._validate_auth_part(key)
        SecurityGuard._validate_auth_part(secret)
        return SecretAuth((key.strip(), secret.strip()))

    @staticmethod
    def validate_and_coerce_auth(auth: AuthCredentials) -> str | SecretAuth | None:
        """Validate and coerce authentication credentials securely (CWE-113, CWE-316).

        Returns:
            str | SecretAuth | None: The validated and coerced authentication credentials.
        """
        __tracebackhide__ = True
        if auth is None:
            return None

        if isinstance(auth, str):
            return SecurityGuard._validate_token(auth)

        if isinstance(auth, tuple):
            return SecurityGuard._validate_basic_auth(auth)

        msg = f"Invalid auth type: expected tuple, str, or None, got {type(auth).__name__}"  # type: ignore[unreachable]
        raise TypeError(msg)


def __getattr__(name: str) -> Any:
    """Resolve legacy v1.9.1 module-level symbols extracted from guardrails lazily.

    Returns:
        Any: Resolved legacy class or exception symbol.
    """
    if name == "ValidationError":
        from mailjet_rest.errors import ValidationError  # ruff: ignore[import-outside-top-level]

        globals()[name] = ValidationError
        return ValidationError
    if name == "HTTPAdapter":
        from requests.adapters import HTTPAdapter  # ruff: ignore[import-outside-top-level]

        globals()[name] = HTTPAdapter
        return HTTPAdapter
    if name == "AuthBase":
        from requests.auth import AuthBase  # ruff: ignore[import-outside-top-level]

        globals()[name] = AuthBase
        return AuthBase
    if name == "HTMLParser":
        from html.parser import HTMLParser  # ruff: ignore[import-outside-top-level]

        globals()[name] = HTMLParser
        return HTMLParser
    msg = f"module {__name__!r} has no attribute {name!r}"
    raise AttributeError(msg)
