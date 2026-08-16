"""Utility module providing security and routing guardrails for the Mailjet SDK.

This module acts as the centralized ingress/egress validation layer, implementing
Defense-in-Depth against OWASP Top 10 vulnerabilities including CWE-22 (Path Traversal),
CWE-918 (SSRF), CWE-400 (Resource Exhaustion), and CWE-117 (Log Forging).
"""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import logging
import math
import re
import ssl
import sys
import tempfile
import unicodedata
import warnings
from functools import lru_cache
from html.parser import HTMLParser
from pathlib import Path
from typing import TYPE_CHECKING, Any, ClassVar, Final, NoReturn
from urllib.parse import quote, unquote, urlparse


if TYPE_CHECKING:
    import requests

    from mailjet_rest.types import TimeoutType

from requests.adapters import HTTPAdapter
from requests.auth import AuthBase

from mailjet_rest.errors import ValidationError


if sys.version_info >= (3, 12):
    from typing import TYPE_CHECKING, override
else:
    from typing_extensions import override


_CRLF_RE: Final = re.compile(r"[\r\n]")
# RFC 9110 strict control characters (blocks all non-printable ASCII except \x09 tab)
_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_PATH_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x1f\x7f]")

# Expanded to include iframe, object, embed, and applet
_XSS_PATTERN: Final = re.compile(r"<(script|svg|iframe|object|embed|applet)|javascript:|onload=", re.IGNORECASE)


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


class SecureHTTPAdapter(HTTPAdapter):
    """Custom HTTP Adapter enforcing modern TLS versions (CWE-319)."""

    @staticmethod
    def _get_secure_ssl_context() -> ssl.SSLContext:
        """Create and return a hardened SSL context enforcing TLS 1.2+.

        Returns:
            ssl.SSLContext: The configured SSL context.
        """
        context = ssl.create_default_context()
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        return context

    @override
    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["ssl_context"] = self._get_secure_ssl_context()
        super().init_poolmanager(*args, **kwargs)

    @override
    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Ensure proxy connections also strictly enforce TLS 1.2+.

        Returns:
            Any: The proxy manager instance.
        """
        proxy_kwargs["ssl_context"] = self._get_secure_ssl_context()
        return super().proxy_manager_for(proxy, **proxy_kwargs)


class SecretAuth(AuthBase):
    """OWASP: Obfuscate credentials in memory dumps and tracebacks (CWE-316).

    Inherits from AuthBase instead of tuple to prevent index/iteration exposure.
    """

    def __init__(self, auth_tuple: tuple[str, str]) -> None:
        """Initialize with API credentials."""
        self._api_key = auth_tuple[0]
        self._api_secret = auth_tuple[1]

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        """Apply Basic Auth headers to the request.

        Returns:
            requests.PreparedRequest: The modified request.
        """
        auth_str = f"{self._api_key}:{self._api_secret}".encode("latin1")
        r.headers["Authorization"] = "Basic " + base64.b64encode(auth_str).decode("ascii")
        return r

    def __hash__(self) -> int:
        """Hash the credentials for dictionary lookups.

        Returns:
            int: The computed hash value.
        """
        return hash((self._api_key, self._api_secret))

    def __eq__(self, other: object) -> bool:
        """Allow equality checks against standard tuples for testing and logic checks.

        Returns:
            bool: True if equal, False otherwise.
        """
        if isinstance(other, tuple):
            # Reconstruct the tuple on the fly for backwards-compatible equality assertions
            return (self._api_key, self._api_secret) == other

        if isinstance(other, SecretAuth):
            # Allow comparison against another SecretAuth instance
            return self._api_key == other._api_key and self._api_secret == other._api_secret

        return False

    def __getitem__(self, index: int) -> NoReturn:
        """Prevent Credential extraction via tuple unpacking / indexing."""
        msg = "Credential extraction via indexing is blocked for security (CWE-316)."
        raise TypeError(msg)

    def __iter__(self) -> Any:
        """Prevent Credential extraction via iteration."""
        msg = "Credential extraction via iteration is blocked for security (CWE-316)."
        raise TypeError(msg)

    def __repr__(self) -> str:
        """Return a safe representation of the credential."""
        return "SecretAuth(***REDACTED***)"


class RedactingFilter(logging.Filter):
    """Deep recursive logging filter to automatically scrub API keys and secrets (CWE-117, CWE-316)."""

    MAX_REDACTION_DEPTH: Final[int] = 4

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

    @staticmethod
    def _redact_str(data: str) -> str:
        try:
            return _get_secret_pattern().sub(r"\1\2********", data)
        except Exception:  # ruff: ignore[blind-except]
            return "[REDACTION_FAILED_UNSAFE_STRING]"

    def _deep_redact(self, data: Any, depth: int = 0) -> Any:
        """Recursively search and scrub secrets from complex nested data structures.

        Returns:
            Any: The fully scrubbed and redacted data structure representation.
        """
        if depth > self.MAX_REDACTION_DEPTH:
            return "[MAX_DEPTH_REACHED]"

        if isinstance(data, str):
            return self._redact_str(data)
        if isinstance(data, dict):
            return {k: self._deep_redact(v, depth + 1) for k, v in data.items()}
        if isinstance(data, list):
            return [self._deep_redact(item, depth + 1) for item in data]
        if isinstance(data, tuple):
            return tuple(self._deep_redact(item, depth + 1) for item in data)
        if isinstance(data, set):
            return {self._deep_redact(item, depth + 1) for item in data}

        return data

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter out sensitive secrets from log records safely.

        Returns:
            bool: Always True (permits the log to write but strictly scrubs the content beforehand).
        """
        try:  # ruff: ignore[too-many-statements-in-try-clause]
            # 1. Redact primary flat string message
            if isinstance(record.msg, str):
                record.msg = self._redact_str(record.msg)

            # 2. Redact tuple/dict args WITHOUT changing their base types
            if isinstance(record.args, (dict, tuple)):
                record.args = self._deep_redact(record.args)

            # 3. Redact dynamically injected 'extra' log attributes
            for attr_name, attr_value in record.__dict__.items():
                if attr_name not in self._STANDARD_ATTRS:
                    record.__dict__[attr_name] = self._deep_redact(attr_value)
        except Exception as e:  # ruff: ignore[blind-except]
            # Failsafe: Never let logging filters crash application execution
            logging.getLogger(__name__).debug("Redaction filter failed: %s", e)
        return True


class SecurityGuard:
    """Centralized OWASP API security and payload guardrails."""

    class _SpamGuardParser(HTMLParser):
        """Internal lightweight HTML analyzer to preemptively catch XSS."""

        def __init__(self) -> None:
            super().__init__()
            self.issues: list[str] = []
            self.has_script = False

        @override
        def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
            # Catch known executable injection points
            if tag.lower() in {"script", "iframe", "object", "embed", "applet"}:
                self.has_script = True
                self.issues.append(f"Blocked executable tag: <{tag}>")

            # Catch any injected event handlers (e.g., onerror, onclick)
            for attr, _ in attrs:
                if attr.lower().startswith("on"):
                    self.has_script = True
                    self.issues.append(f"Blocked event handler: {attr}")

    VOLATILE_IDEMPOTENCY_KEYS: ClassVar[frozenset[str]] = frozenset({"CustomID", "EventPayload", "SandboxMode"})
    ALLOWED_KWARGS: ClassVar[frozenset[str]] = frozenset(
        {"proxies", "cert", "stream", "verify", "allow_redirects", "files"}
    )

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

        Raises:
            ValueError: If the scheme or hostname violates zero-trust policies.
        """
        parsed = urlparse(url)

        # 1. Enforce Safe Schemes (Block file://, dict://, gopher://, etc.)
        if parsed.scheme not in {"http", "https"}:
            msg = f"Security Alert (CWE-918): Invalid scheme '{parsed.scheme}'. Only http/https allowed."
            raise ValueError(msg)

        hostname = parsed.hostname or ""

        # 2. Allowlist (Production + Local CI/CD loopbacks)
        allowed_exact_hosts = frozenset(
            {
                allowed_root_domain,
                f"api.{allowed_root_domain}",
                "localhost",
                "127.0.0.1",
                "::1",  # Include IPv6 loopback for modern CI environments
            }
        )

        # Safe if it's an exact match OR a valid subdomain of the trusted root
        is_safe = hostname in allowed_exact_hosts or hostname.endswith(f".{allowed_root_domain}")

        if not is_safe:
            msg = (
                f"Security Alert (CWE-918): Hostname '{hostname}' is not permitted. "
                f"Must be a '{allowed_root_domain}' domain or a local loopback for testing."
            )
            raise ValueError(msg)

    @staticmethod
    def check_request_security(kwargs: dict[str, Any]) -> None:
        """Proactively warn developers about unencrypted proxies."""
        proxies = kwargs.get("proxies")
        if proxies and any(str(p).startswith("http://") for p in proxies.values()):
            warnings.warn("Security Warning: Unencrypted HTTP proxy detected.", UserWarning, stacklevel=3)

    @staticmethod
    def sanitize_headers(headers: dict[str, str]) -> dict[str, str]:
        """Prevent HTTP Header Injection (CWE-113).

        Returns:
            dict[str, str]: The sanitized headers safely screened for CRLF injections.
        """
        clean_headers = {}
        for k, v in headers.items():
            if _CRLF_RE.search(k) or _CRLF_RE.search(str(v)):
                sys.audit("mailjet.security.header_injection", k)
                msg = f"Security Violation: CRLF injection detected in header '{k}'"
                raise ValueError(msg)
            clean_headers[k] = v
        return clean_headers

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
            dict[str, Any]: The analysis report containing boolean 'is_safe' and any 'issues' strings.
        """
        if not html_content or html_content.isspace():
            return {"is_safe": True, "issues": []}

        # Defense-in-Depth against Memory/CPU exhaustion (CWE-400)
        # Cap HTML processing at 5MB prior to standard library parsing.
        if len(html_content) > 5 * 1024 * 1024:
            sys.audit("mailjet.security.resource_exhaustion", "HTMLPart")
            msg = "Security Violation: HTML payload exceeds maximum safe length."
            raise ValueError(msg)

        if _XSS_PATTERN.search(html_content):
            sys.audit("mailjet.security.xss_attempt", "HTMLPart")
            msg = "Security Violation: HTML contains executable Javascript/XSS vectors."
            raise ValueError(msg)

        parser = SecurityGuard._SpamGuardParser()
        try:
            parser.feed(html_content)
        except Exception as e:
            # Failsafe: Catch RecursionError, MemoryError, etc. to prevent DoS crashes
            msg = f"Fatal HTML parsing error (DoS protection triggered): {e}"
            raise ValidationError(msg) from e

        if parser.has_script:
            sys.audit("mailjet.security.xss_attempt", "HTMLPart")
            msg = "Security Violation: HTML contains blocked script/event execution tags."
            raise ValueError(msg)

        return {"is_safe": not parser.has_script, "issues": parser.issues}

    @staticmethod
    def generate_payload_fingerprint(payload: dict[str, Any] | list[Any]) -> str:
        """Generates a safe SHA-256 Idempotency hash for the exact JSON payload.

        Returns:
            str: The generated SHA-256 hash.
        """

        def _deep_strip(data: Any, depth: int = 0, seen: set[int] | None = None) -> Any:
            if seen is None:
                seen = set()

            # Active Cycle Detection (CWE-674) to prevent RecursionError crashes
            if id(data) in seen:
                return "[Circular]"

            if depth > 50:
                msg = "Security Violation: Payload exceeds maximum safe nesting depth."
                raise ValueError(msg)

            if isinstance(data, dict):
                seen.add(id(data))
                return {
                    k: _deep_strip(v, depth + 1, seen.copy())
                    for k, v in data.items()
                    if k not in SecurityGuard.VOLATILE_IDEMPOTENCY_KEYS
                }
            if isinstance(data, (list, tuple, set)):
                seen.add(id(data))
                return [_deep_strip(item, depth + 1, seen.copy()) for item in data]
            return data

        try:
            safe_payload = _deep_strip(payload)
            serialized = json.dumps(safe_payload, sort_keys=True, default=str)
            return hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        except Exception as e:
            msg = "Payload hashing failed due to malformed or deeply nested structure."
            raise ValueError(msg) from e

    @staticmethod
    def validate_attachment_path(file_path: Path | str, safe_base_dir: Path | str | None = None) -> Path:
        """Prevent Path Traversal (CWE-22) via strict resolution boundary checks.

        Falls back to Zero-Trust OS directory restrictions if no safe_base_dir is supplied.

        Returns:
            Path: The resolved and strictly validated pathlib.Path object.
        """
        original_path = str(file_path)
        target = Path(file_path).resolve()

        if safe_base_dir is not None:
            base = Path(safe_base_dir).resolve()
            if not target.is_relative_to(base):
                sys.audit("mailjet.security.path_traversal", str(target))
                msg = f"Security Violation: Traversal detected. '{target}' is outside '{base}'."
                raise ValueError(msg)
        else:
            # Fallback zero-trust checks if no specific sandbox is provided
            if ".." in original_path:
                msg = "Security Alert (CWE-22): Path traversal tokens ('..') are explicitly forbidden."
                raise ValueError(msg)

            # Allow files residing in the OS temporary directory
            with contextlib.suppress(Exception):
                temp_dir = Path(tempfile.gettempdir()).resolve()
                if target.is_relative_to(temp_dir):
                    return target

            # Cross-platform component and prefix check for sensitive system directories
            forbidden_roots = ("/etc", "/var", "/root", "/boot", "C:\\Windows", "C:\\System32")
            path_str = str(target).lower()
            if any(path_str.startswith(root.lower()) for root in forbidden_roots):
                msg = "Security Alert: Access to sensitive OS system directories is explicitly forbidden."
                raise ValueError(msg)

            forbidden_components = {"etc", "sys", "proc", "dev", "windows", "system32", "root", "boot"}
            if any(part.lower() in forbidden_components for part in target.parts):
                msg = "Security Alert: Access to sensitive OS system directories is explicitly forbidden."
                raise ValueError(msg)

        if not target.exists() or not target.is_file():
            msg = f"Attachment not found or is not a file: {target}"
            raise FileNotFoundError(msg)

        return target

    @staticmethod
    def check_file_size(path: Path, max_size_bytes: int = 15 * 1024 * 1024) -> None:
        """Prevent Resource Exhaustion (CWE-400). Limit defaults to 15MB."""
        size = path.stat().st_size
        if size > max_size_bytes:
            msg = f"Security Violation: File '{path.name}' exceeds safe threshold."
            raise ValueError(msg)

    @staticmethod
    def _validate_scalar_timeout(timeout: Any) -> float:
        """Helper to validate a single scalar timeout value (CWE-400).

        Args:
            timeout (Any): The timeout value to validate.

        Returns:
            float: The validated scalar timeout in seconds.
        """
        if not isinstance(timeout, (int, float)):
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
    def normalize_domain(email_or_domain: str) -> str:
        """Prevent Unicode Homograph attacks by encoding IDNs to Punycode (RFC 3490).

        Returns:
            str: The fully normalized punycode domain representation.
        """
        if not email_or_domain:
            return email_or_domain
        parts = email_or_domain.rsplit("@", 1)

        if len(parts) == 2:
            local, domain = parts
            try:
                puny_domain = domain.encode("idna").decode("ascii")
            except Exception as e:
                msg = f"Invalid IDN in email: {email_or_domain}"
                raise ValueError(msg) from e
            else:
                return f"{local}@{puny_domain}"
        else:
            try:
                return email_or_domain.encode("idna").decode("ascii")
            except Exception as e:
                msg = f"Invalid IDN: {email_or_domain}"
                raise ValueError(msg) from e

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

        # =================================================================
        # 1. EVALUATION STATE (Phantom Decoding)
        # =================================================================
        # CWE-116: Defeat Double-Encoding bypasses
        test_decoded = raw_str
        for _ in range(3):
            new_decoded = unquote(test_decoded)
            if new_decoded == test_decoded:
                break
            test_decoded = new_decoded
        else:
            msg = "Security Alert (CWE-116): Excessive URL encoding detected."
            raise ValueError(msg)

        # CWE-128: Unicode Normalization on the testing string
        test_decoded = unicodedata.normalize("NFKC", test_decoded)

        # CWE-20: Strict path validation
        if _PATH_CONTROL_CHAR_RE.search(test_decoded):
            sys.audit("mailjet.security.control_characters", "path_segment")
            msg = "Security Alert (CWE-20): Forbidden control characters."
            raise ValueError(msg)

        # CWE-22: Path Traversal
        if ".." in test_decoded or "/" in test_decoded or "\\" in test_decoded:
            sys.audit("mailjet.security.path_traversal", test_decoded)
            msg = "Security Alert (CWE-22): Path traversal attempt."
            raise ValueError(msg)

        # CWE-94: Template Injection
        if any(marker in test_decoded for marker in ("{{", "}}", "{%")):
            msg = "Security Alert (CWE-94): Template injection attempt."
            raise ValueError(msg)

        # CWE-79: XSS
        if _XSS_PATTERN.search(test_decoded):
            msg = "Security Alert (CWE-79): XSS attempt detected."
            raise ValueError(msg)

        # =================================================================
        # 2. TRANSPORT STATE (Safe Construction)
        # =================================================================
        # We quote the ORIGINAL raw string. This guarantees that if a user passes
        # a legitimate email like "user%name@example.com", the '%' is safely encoded
        # to '%25' without being destructively parsed as a bad hex escape.
        return quote(raw_str, safe="").replace(".", "%2E")

    @staticmethod
    def sanitize_log_trace(trace_val: Any) -> str:
        """Prevent Log Forging (CWE-117) by stripping control characters.

        Returns:
            str: The strictly formatted safe tracing suffix stripped of structural tokens.
        """
        if not trace_val:
            return ""
        return re.sub(r"\s+", "_", str(trace_val))

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
        return clean_token

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
        for item in (key, secret):
            if not item or not item.strip():
                msg = "Auth credentials cannot be empty or whitespace-only."
                raise ValueError(msg)
            if _CRLF_RE.search(item) or _CONTROL_CHAR_RE.search(item):
                msg = "Auth credentials contain forbidden control characters."
                raise ValueError(msg)
            if any(unicodedata.category(c) in {"Zs", "Cc", "Cf"} for c in item if c != " "):
                msg = "Auth credentials contain invalid whitespace or control characters."
                raise ValueError(msg)
        return SecretAuth((key.strip(), secret.strip()))

    @staticmethod
    def validate_and_coerce_auth(auth: str | tuple[str, str] | None) -> str | SecretAuth | None:
        """Validate and coerce authentication credentials securely (CWE-113, CWE-316).

        Returns:
            str | SecretAuth | None: The validated and coerced authentication credentials.
        """
        if auth is None:
            return None

        if isinstance(auth, str):
            return SecurityGuard._validate_token(auth)

        if isinstance(auth, tuple):
            return SecurityGuard._validate_basic_auth(auth)

        msg = f"Invalid auth type: expected tuple, str, or None, got {type(auth).__name__}"  # type: ignore[unreachable]
        raise TypeError(msg)
