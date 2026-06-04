"""Utility module providing security and routing guardrails for the Mailjet SDK."""

import logging
import re
import ssl
import sys
import warnings
from functools import lru_cache
from pathlib import Path
from typing import Any, ClassVar, Final
from urllib.parse import quote, urlparse

from requests.adapters import HTTPAdapter


if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


_CRLF_RE: Final = re.compile(r"[\r\n]")


# Regex to catch Authorization headers and common API key patterns
@lru_cache(maxsize=1)
def _get_secret_pattern() -> re.Pattern[str]:
    """Lazy-compile strict patterns to minimize cold-boot overhead.

    ReDoS prevented by eliminating overlapping quantifiers (+)
    and enforcing strict finite bounds ({1,5} and {1,200}).

    Returns:
        re.Pattern[str]: Compiled regular expression for secret pattern matching.
    """
    # Group 1: The key/header name (e.g., Authorization)
    # Group 2: The separator and scheme (e.g., ': Bearer ')
    # Group 3: The actual secret (matched but NOT included in the substitution)
    return re.compile(
        r"(?i)(Authorization|api[_-]key|api[_-]secret|token)([:\s=]{1,5}(?:(?:Bearer|Basic|Token)\s{1,5})?)([^\s'\"]{1,200})"
    )


class SecureHTTPAdapter(HTTPAdapter):
    """Custom HTTP Adapter enforcing modern TLS versions (CWE-319)."""

    def init_poolmanager(self, connections: int, maxsize: int, block: bool = False, **pool_kwargs: Any) -> None:
        """Initialize the pool manager with enforced TLS 1.2+ configuration."""
        context = ssl.create_default_context()
        # Enforce TLS 1.2+ to prevent downgrade attacks (aligns with NIST SP 800-52)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        pool_kwargs["ssl_context"] = context
        super().init_poolmanager(connections, maxsize, block, **pool_kwargs)


class RedactingFilter(logging.Filter):
    """Filter that intercepts and masks sensitive credentials in log records."""

    @override
    def filter(self, record: logging.LogRecord) -> bool:
        """Filter sensitive patterns from log records.

        Redact message content (e.g., logger.debug("Auth: %s", key))

        Returns:
            bool
        """
        if isinstance(record.msg, str):
            record.msg = _get_secret_pattern().sub(r"\1\2********", record.msg)

        if isinstance(record.args, tuple) and record.args:
            new_args = []
            for arg in record.args:
                if isinstance(arg, str):
                    new_args.append(_get_secret_pattern().sub(r"\1\2********", arg))
                else:
                    new_args.append(arg)  # type: ignore[arg-type]
            record.args = tuple(new_args)
        elif isinstance(record.args, dict) and record.args:
            new_dict_args = {}
            for k, v in record.args.items():
                if isinstance(v, str):
                    new_dict_args[k] = _get_secret_pattern().sub(r"\1\2********", v)
                else:
                    new_dict_args[k] = v
            record.args = new_dict_args

        return True


class SecurityGuard:
    """Centralized security validation and sanitization (Defense in Depth)."""

    _audit_hook_installed: ClassVar[bool] = False

    @staticmethod
    def _security_audit_listener(event: str, args: tuple[Any, ...]) -> None:
        """Listener for audit events to provide system-level security logging.

        This method intercepts native Python audit events. If the event is
        specific to the Mailjet SDK, it logs the event for SIEM integration.

        Args:
            event (str): The name of the triggered audit event.
            args (tuple[Any, ...]): The arguments associated with the audit event.
        """
        if event.startswith("mailjet."):
            logging.getLogger(__name__).warning("SECURITY AUDIT [%s]: %s", event, args)

    @classmethod
    def enable_audit_logging(cls) -> None:
        """Optional registration of the runtime security audit hook (PEP 578).

        Securely registers the audit listener at the interpreter level.
        Uses a class-level flag to ensure the hook is registered only once.
        """
        if not cls._audit_hook_installed and hasattr(sys, "addaudithook"):
            sys.addaudithook(cls._security_audit_listener)
            cls._audit_hook_installed = True

    @staticmethod
    def validate_attribute_access(class_name: str, name: str) -> None:
        """Prevent magic method traps and secret leakage.

        Args:
            class_name (str): The name of the calling class.
            name (str): The name of the requested attribute.

        Raises:
            AttributeError: If attempting to access private or intentionally removed attributes.
        """
        if name.startswith("_"):
            msg = f"'{class_name}' object has no attribute '{name}'"
            raise AttributeError(msg)
        if name == "auth":
            err_msg = "The 'auth' attribute was intentionally removed (CWE-316)."
            raise AttributeError(err_msg)

    @staticmethod
    def sanitize_log_trace(val: Any) -> str:
        """Strictly sanitize log values to prevent Log Forging (CWE-117).

        Args:
            val (Any): The input value to sanitize.

        Returns:
            str: The sanitized string value.
        """
        # CAST TO STRING FIRST to prevent TypeError on ints/floats
        val_str = str(val)

        # Fail-fast on insanely large strings (CWE-400 Resource Exhaustion)
        if len(val_str) > 1000:
            val_str = val_str[:1000] + "... [TRUNCATED]"

        return _CRLF_RE.sub("", val_str)

    @staticmethod
    def check_request_security(kwargs: dict[str, Any]) -> None:
        """Evaluate request kwargs for security risks (MitM, Proxies).

        Args:
            kwargs (dict[str, Any]): The dictionary of keyword arguments for the request.
        """
        if not kwargs.get("verify", True):
            # Fail-closed: Explicitly crash on insecure requests
            msg = "Security Violation: Mailjet API TLS verification cannot be disabled in production. Set verify=True."
            raise ValueError(msg)

        proxies = kwargs.get("proxies")
        if proxies and any(str(p).startswith("http://") for p in proxies.values()):
            msg = "Security Warning: Unencrypted HTTP proxy detected."
            warnings.warn(msg, UserWarning, stacklevel=4)

    @staticmethod
    def validate_config_url(api_url: str, allowed_root_domain: str = "mailjet.com") -> None:
        """Validate API URL for secure transport and Anti-SSRF (CWE-918).

        Args:
            api_url (str): The base URL for the Mailjet API.
            allowed_root_domain (str): The permitted root domain to prevent SSRF.

        Raises:
            ValueError: If the scheme is not HTTPS or the hostname is missing.
        """
        parsed = urlparse(api_url)

        # 1. Enforce HTTPS (Transport Layer Security)
        if parsed.scheme != "https":
            msg = f"Security Violation: api_url scheme must be 'HTTPS', got '{parsed.scheme}'."
            raise ValueError(msg)

        # 2. Enforce Hostname existence
        if not parsed.hostname:
            err_msg = "Security Violation: Missing hostname in API URL."
            raise ValueError(err_msg)

        # 3. Fail-Closed Domain Validation (Prevent SSRF)
        hostname = parsed.hostname.lower()

        # Strictly enforce root OR subdomain match
        if hostname != allowed_root_domain and not hostname.endswith(f".{allowed_root_domain}"):
            # This protects against SSRF attempts where an attacker tries to
            # point the client to an internal or malicious domain.
            msg = f"Security Violation: '{parsed.hostname}' is not a trusted Mailjet domain."
            raise ValueError(msg)

    @staticmethod
    def validate_dx_routing(version: str, name_lower: str, resource_lower: str) -> None:
        """Emit warnings for ambiguous routing scenarios to improve Developer Experience.

        Args:
            version (str): The current API version string.
            name_lower (str): The lowercase endpoint name.
            resource_lower (str): The lowercase resource identifier.
        """
        msg = ""
        if name_lower == "send" and version not in {"v3", "v3.1"}:
            msg = "Mailjet API Ambiguity: The Send API is only available on 'v3' and 'v3.1'."
        elif version == "v1" and resource_lower == "template":
            msg = "Mailjet API Ambiguity: Content API (v1) uses plural '/templates'."
        elif version.startswith("v3") and resource_lower == "templates":
            msg = f"Mailjet API Ambiguity: Email API ({version}) uses singular '/template'."

        if msg:
            warnings.warn(msg, DeprecationWarning, stacklevel=4)

    @staticmethod
    def validate_crlf_headers(custom_headers: dict[str, str]) -> None:
        """Prevent HTTP Header Injection (CWE-113).

        Args:
            custom_headers (dict[str, str]): The dictionary of custom headers to validate.

        Raises:
            ValueError: If CRLF characters are detected in any header value.
        """
        for key, value in custom_headers.items():
            if _CRLF_RE.search(str(value)):
                msg = f"Security Violation: CRLF Injection detected in header '{key}'."
                raise ValueError(msg)

    @staticmethod
    def validate_attachment_path(file_path: str | Path, safe_base_dir: str | Path | None = None) -> Path:
        """Prevent Path Traversal (CWE-22) and Symlink escapes.

        Args:
            file_path: The file path requested for attachment.
            safe_base_dir: An optional absolute directory to jail the file read.

        Returns:
            Path: The resolved absolute path if validation passes.

        Raises:
            ValueError: If traversal or symlink violation is detected.
            FileNotFoundError: If the file does not exist.
        """
        path = Path(file_path).resolve()

        # Enforce Path Jailing if a safe boundary is defined
        if safe_base_dir:
            base = Path(safe_base_dir).resolve()
            if not path.is_relative_to(base):
                sys.audit("mailjet.security.path_traversal", str(path))
                msg = f"Security Violation: Path Traversal detected. '{path}' is outside restricted directory '{base}'."
                raise ValueError(msg)

        if not path.is_file():
            msg = f"Attachment not found or is not a regular file: {path}"
            raise FileNotFoundError(msg)

        return path

    @staticmethod
    def check_file_size(path: Path, max_size_bytes: int = 15 * 1024 * 1024) -> None:
        """Prevent Resource Exhaustion (CWE-400). Mailjet limits payloads to 15MB."""
        size = path.stat().st_size
        if size > max_size_bytes:
            msg = f"Security Violation: File '{path.name}' ({size} bytes) exceeds the safe threshold of {max_size_bytes} bytes."
            raise ValueError(msg)

    @staticmethod
    def sanitize_segment(segment: Any) -> str:
        """Poka-yoke: Safely encode path segments preventing CWE-22 (Path Traversal).

        Args:
            segment: Dynamic ID or action value crossing the trust boundary.

        Returns:
            str: URL-encoded path component string.
        """
        if segment is None:
            return ""

        clean_str = str(segment).replace("\r", "").replace("\n", "")
        # quote() ignores dots. We explicitly encode them to prevent
        # strict ".." traversal when injected into middle of URI templates.
        return quote(clean_str, safe="").replace(".", "%2E")
