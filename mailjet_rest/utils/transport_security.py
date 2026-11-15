"""Transport-layer TLS context caching, keep-alive adapter, and credential auth."""

from __future__ import annotations

import base64
import hmac
import os
import re
import socket
import ssl
import sys
from functools import lru_cache
from pathlib import Path
from typing import TYPE_CHECKING, Any, Final, NoReturn

from requests.adapters import HTTPAdapter
from requests.auth import AuthBase
from requests.utils import DEFAULT_CA_BUNDLE_PATH
from urllib3.connection import HTTPConnection


if TYPE_CHECKING:
    import requests

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

_KEEPALIVE_OPTION: Final[tuple[int, int, int]] = (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
_DEFAULT_SOCKET_OPTIONS: Final[tuple[Any, ...]] = tuple(HTTPConnection.default_socket_options or ())
_KEEPALIVE_SOCKET_OPTIONS: Final[tuple[Any, ...]] = (
    _DEFAULT_SOCKET_OPTIONS
    if _KEEPALIVE_OPTION in _DEFAULT_SOCKET_OPTIONS
    else (*_DEFAULT_SOCKET_OPTIONS, _KEEPALIVE_OPTION)
)


def resolve_tls_verify(verify: Any) -> bool | str:
    """Validate TLS verification flag or custom CA bundle path (CWE-295).

    Returns:
        bool | str: True for default CA verification, or validated CA bundle path string.
    """
    if verify is False or verify is None:
        sys.audit("mailjet.security.tls_disabled", str(verify))
        msg = "Security Violation: Mailjet API TLS verification cannot be disabled (verify=False is forbidden)."
        raise ValueError(msg)

    if verify is True:
        return True

    if isinstance(verify, (str, os.PathLike)):
        raw_verify = os.fspath(verify)
        if not isinstance(raw_verify, str):
            msg = f"Invalid CA bundle path type: expected str or os.PathLike[str], got {type(raw_verify).__name__}."
            raise TypeError(msg)
        if not raw_verify.strip() or _CONTROL_CHAR_RE.search(raw_verify):
            msg = "Invalid CA bundle path: must be a non-empty path without control characters."
            raise ValueError(msg)
        ca_path = Path(raw_verify).expanduser()
        if not ca_path.exists() or not ca_path.is_file():
            msg = f"Custom CA bundle path does not exist or is not a file: {ca_path}"
            raise ValueError(msg)
        return str(ca_path)

    msg = f"Invalid 'verify' type: expected bool, str, or PathLike, got {type(verify).__name__}."
    raise TypeError(msg)


@lru_cache(maxsize=8)
def _cached_ssl_context(ca_bundle: str | None, mtime_ns: int, size: int) -> ssl.SSLContext:
    """Build and cache an isolated TLS 1.2+ SSLContext keyed on CA bundle identity and mtime/size.

    Returns:
        ssl.SSLContext: Configured SSL context with isolated CA trust store.
    """
    _ = (mtime_ns, size)
    if ca_bundle is not None:
        context = ssl.create_default_context(cafile=ca_bundle)
    else:
        context = ssl.create_default_context()
        if DEFAULT_CA_BUNDLE_PATH and Path(DEFAULT_CA_BUNDLE_PATH).is_file():
            context.load_verify_locations(cafile=DEFAULT_CA_BUNDLE_PATH)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.check_hostname = True
    context.verify_mode = ssl.CERT_REQUIRED
    context.options |= getattr(ssl, "OP_NO_COMPRESSION", 0)
    return context


def get_secure_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Return a hardened TLS 1.2+ SSLContext, invalidating cache when a custom CA file changes.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    if ca_bundle is not None:
        st = Path(ca_bundle).stat()
        return _cached_ssl_context(ca_bundle, st.st_mtime_ns, st.st_size)
    return _cached_ssl_context(None, 0, 0)


def _build_tls_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Create or retrieve a hardened SSLContext enforcing TLS 1.2+ and isolated CA trust stores.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    return get_secure_ssl_context(ca_bundle)


class SecureHTTPAdapter(HTTPAdapter):
    """Custom HTTP Adapter enforcing TLS 1.2+, isolated CA trust stores, and TCP keep-alive."""

    def __init__(self, ca_bundle: str | None = None, **kwargs: Any) -> None:
        """Initialize the TLS adapter with an optional custom CA bundle path."""
        self._ca_bundle = ca_bundle
        self._ssl_context = _build_tls_context(ca_bundle)
        super().__init__(**kwargs)

    @staticmethod
    def _get_secure_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
        """Create and return a hardened SSL context enforcing TLS 1.2+.

        Returns:
            ssl.SSLContext: The configured SSL context.
        """
        return _build_tls_context(ca_bundle)

    @override
    def init_poolmanager(self, *args: Any, **kwargs: Any) -> None:
        kwargs["ssl_context"] = self._ssl_context
        kwargs.setdefault("socket_options", _KEEPALIVE_SOCKET_OPTIONS)
        super().init_poolmanager(*args, **kwargs)  # type: ignore[no-untyped-call]

    @override
    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Ensure proxy connections also strictly enforce TLS 1.2+ and TCP keep-alive.

        Returns:
            Any: The proxy manager instance.
        """
        proxy_kwargs["ssl_context"] = self._ssl_context
        proxy_kwargs.setdefault("socket_options", _KEEPALIVE_SOCKET_OPTIONS)
        return super().proxy_manager_for(proxy, **proxy_kwargs)  # type: ignore[no-untyped-call]

    @override
    def cert_verify(self, conn: Any, url: str, verify: Any, cert: Any) -> None:
        """Enforce strict TLS verification and isolate per-call CA/client-cert SSL contexts."""
        resolved = resolve_tls_verify(verify)
        super().cert_verify(conn, url, resolved, cert)  # type: ignore[no-untyped-call]
        if url.lower().startswith("https"):
            needs_isolated_ctx = (
                cert is not None
                or (isinstance(resolved, str) and resolved != self._ca_bundle)
                or (resolved is True and self._ca_bundle is not None)
            )
            if needs_isolated_ctx:
                target_ca = resolved if isinstance(resolved, str) else None
                conn.ssl_context = _build_tls_context(target_ca)
            else:
                conn.ssl_context = self._ssl_context
            # Clear ca_certs/ca_cert_dir because conn.ssl_context already holds the exact trust store;
            # otherwise urllib3 mutates the shared SSLContext on handshake.
            conn.ca_certs = None
            conn.ca_cert_dir = None


class SecretAuth(AuthBase):
    """OWASP: Obfuscate credentials in memory dumps and tracebacks (CWE-316).

    Kept unslotted in 1.x because requests.auth.AuthBase defines no __slots__.
    Pre-encodes the Basic Authorization header in __init__.
    """

    def __init__(self, auth_tuple: tuple[str, str]) -> None:
        """Initialize with API credentials and pre-compute Basic Auth header."""
        __tracebackhide__ = True
        self._api_key = auth_tuple[0]
        self._api_secret = auth_tuple[1]
        auth_bytes = f"{self._api_key}:{self._api_secret}".encode("latin1")
        self._auth_header = "Basic " + base64.b64encode(auth_bytes).decode("ascii")

    def __call__(self, r: requests.PreparedRequest) -> requests.PreparedRequest:
        """Apply pre-computed Basic Auth headers to the request.

        Returns:
            requests.PreparedRequest: The modified request.
        """
        __tracebackhide__ = True
        r.headers["Authorization"] = self._auth_header
        return r

    def __hash__(self) -> int:
        """Hash the credentials for dictionary lookups.

        Returns:
            int: The computed hash value.
        """
        return hash((self._api_key, self._api_secret))

    def __eq__(self, other: object) -> bool:
        """Compare credentials in constant time using hmac.compare_digest.

        Returns:
            bool: True if equal, False otherwise.
        """
        if isinstance(other, SecretAuth):
            other_key = other._api_key
            other_secret = other._api_secret
        elif isinstance(other, tuple) and len(other) == 2 and all(isinstance(item, str) for item in other):
            other_key, other_secret = other
        else:
            return False

        try:
            key_match = hmac.compare_digest(self._api_key.encode("utf-8"), other_key.encode("utf-8"))
            secret_match = hmac.compare_digest(self._api_secret.encode("utf-8"), other_secret.encode("utf-8"))
        except UnicodeEncodeError:
            return False
        return bool(key_match & secret_match)

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

    def __str__(self) -> str:
        """Return a safe string representation of the credential."""
        return "SecretAuth(***REDACTED***)"
