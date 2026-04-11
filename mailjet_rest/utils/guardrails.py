"""Utility module providing security and routing guardrails for the Mailjet SDK."""

import warnings
from typing import Any
from urllib.parse import urlparse


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


def sanitize_log_trace(val: Any) -> str:
    """Sanitize log values to prevent Log Forging (CWE-117).

    Args:
        val (Any): The input value to sanitize.

    Returns:
        str: The sanitized string value.
    """
    return str(val).replace("\n", "_").replace("\r", "_")


def check_request_security(kwargs: dict[str, Any]) -> None:
    """Evaluate request kwargs for security risks (MitM, Proxies).

    Args:
        kwargs (dict[str, Any]): The dictionary of keyword arguments for the request.
    """
    if kwargs.get("verify") is False:
        msg = "Security Warning: Disabling TLS verification exposes the client to MitM attacks."
        warnings.warn(msg, UserWarning, stacklevel=4)

    proxies = kwargs.get("proxies")
    if proxies and any(str(p).startswith("http://") for p in proxies.values()):
        msg = "Security Warning: Unencrypted HTTP proxy detected."
        warnings.warn(msg, UserWarning, stacklevel=4)


def validate_config_url(api_url: str, allowed_root_domain: str = "mailjet.com") -> None:
    """Validate API URL for secure transport and Anti-SSRF (CWE-918).

    Args:
        api_url (str): The base URL for the Mailjet API.
        allowed_root_domain (str): The permitted root domain to prevent SSRF.

    Raises:
        ValueError: If the scheme is not HTTPS or the hostname is missing.
    """
    parsed = urlparse(api_url)
    if parsed.scheme != "https":
        msg = f"Secure connection required: api_url scheme must be 'https', got '{parsed.scheme}'."
        raise ValueError(msg)
    if not parsed.hostname:
        err_msg = "Invalid api_url: missing hostname."
        raise ValueError(err_msg)

    hostname = parsed.hostname.lower()
    # Explicitly verify exact match OR valid subdomain match to prevent CWE-20/CWE-918 bypass
    if hostname != allowed_root_domain and not hostname.endswith(f".{allowed_root_domain}"):
        warn_msg = f"Security Warning: api_url points to a non-Mailjet domain ({parsed.hostname})."
        warnings.warn(warn_msg, UserWarning, stacklevel=3)


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


def validate_crlf_headers(custom_headers: dict[str, str]) -> None:
    """Prevent HTTP Header Injection (CWE-113).

    Args:
        custom_headers (dict[str, str]): The dictionary of custom headers to validate.

    Raises:
        ValueError: If CRLF characters are detected in any header value.
    """
    for key, value in custom_headers.items():
        val_str = str(value)
        if "\n" in val_str or "\r" in val_str:
            err_msg = f"CRLF Injection detected in header '{key}'"
            raise ValueError(err_msg)
