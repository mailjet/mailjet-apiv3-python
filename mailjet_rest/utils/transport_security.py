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
    import httpx2
    import requests

    from mailjet_rest.types import CertConfig

if sys.version_info >= (3, 12):
    from typing import override
else:
    from typing_extensions import override


_CONTROL_CHAR_RE: Final = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")

_KEEPALIVE_OPTION: Final[tuple[int, int, int]] = (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
_HTTP_CONNECTION_CLS: Any = HTTPConnection
_DEFAULT_SOCKET_OPTIONS: Final[tuple[Any, ...]] = tuple(_HTTP_CONNECTION_CLS.default_socket_options or ())
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

        try:
            ca_path = Path(raw_verify).expanduser()
        except RuntimeError as e:
            msg = f"Invalid CA bundle path '{raw_verify}': could not determine home directory."
            raise ValueError(msg) from e

        if not ca_path.exists() or not ca_path.is_file():
            msg = f"Custom CA bundle path does not exist or is not a file: {ca_path}"
            raise ValueError(msg)
        return str(ca_path)

    msg = f"Invalid 'verify' type: expected bool, str, or PathLike, got {type(verify).__name__}."
    raise TypeError(msg)


def _new_secure_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Create a fresh hardened TLS 1.2+ SSLContext with isolated CA trust store.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
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


@lru_cache(maxsize=8)
def _cached_ssl_context(ca_bundle: str | None, mtime_ns: int, size: int) -> ssl.SSLContext:
    """Build and cache an isolated TLS 1.2+ SSLContext keyed on CA bundle identity and mtime/size.

    Returns:
        ssl.SSLContext: Configured SSL context with isolated CA trust store.
    """
    _ = (mtime_ns, size)
    return _new_secure_ssl_context(ca_bundle)


def get_secure_ssl_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Return a hardened TLS 1.2+ SSLContext, invalidating cache when a custom CA file changes.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    if ca_bundle is not None:
        st = Path(ca_bundle).stat()
        return _cached_ssl_context(ca_bundle, st.st_mtime_ns, st.st_size)
    return _cached_ssl_context(None, 0, 0)


def build_ssl_context_with_cert(ca_bundle: str | None = None, cert: CertConfig = None) -> ssl.SSLContext:
    """Return a hardened TLS 1.2+ SSLContext with an optional uncached client certificate chain.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    if cert is None:
        return get_secure_ssl_context(ca_bundle)
    context = _new_secure_ssl_context(ca_bundle)
    if isinstance(cert, (tuple, list)):
        if len(cert) != 2:
            msg = "Client 'cert' tuple must contain (certfile, keyfile)."  # type: ignore[unreachable]
            raise ValueError(msg)
        context.load_cert_chain(certfile=cert[0], keyfile=cert[1])
    elif isinstance(cert, (str, os.PathLike)):
        context.load_cert_chain(certfile=cert)
    else:
        msg = f"Invalid 'cert' type: expected str, PathLike, or (certfile, keyfile) tuple, got {type(cert).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    return context


def _build_tls_context(ca_bundle: str | None = None) -> ssl.SSLContext:
    """Create or retrieve a hardened SSLContext enforcing TLS 1.2+ and isolated CA trust stores.

    Returns:
        ssl.SSLContext: Configured SSL context.
    """
    return get_secure_ssl_context(ca_bundle)


def coerce_httpx2_timeout(httpx2_mod: Any, timeout_val: Any) -> Any:
    """Convert Mailjet timeout values into an ``httpx2.Timeout`` configuration.

    Returns:
        Any: Configured ``httpx2.Timeout`` instance or original timeout value.
    """
    if isinstance(timeout_val, tuple) and len(timeout_val) == 2:
        connect_t, read_t = float(timeout_val[0]), float(timeout_val[1])
        return httpx2_mod.Timeout(read_t, connect=connect_t, read=read_t, write=read_t, pool=connect_t)
    if isinstance(timeout_val, (int, float)) and not isinstance(timeout_val, bool):
        return httpx2_mod.Timeout(float(timeout_val))
    return timeout_val


def build_httpx2_transport(
    httpx2_mod: Any,
    resolved_verify: bool | str,
    *,
    pool_connections: int,
    pool_maxsize: int,
    proxy: Any = None,
    cert: CertConfig = None,
) -> httpx2.AsyncHTTPTransport:
    """Construct a hardened TLS 1.2+ ``httpx2.AsyncHTTPTransport`` with TCP keep-alive options.

    Returns:
        httpx2.AsyncHTTPTransport: Configured async HTTP transport instance.
    """
    ca_bundle = resolved_verify if isinstance(resolved_verify, str) else None
    ssl_ctx = build_ssl_context_with_cert(ca_bundle, cert) if cert is not None else get_secure_ssl_context(ca_bundle)
    limits = httpx2_mod.Limits(
        max_connections=pool_maxsize,
        max_keepalive_connections=pool_connections,
    )
    transport: httpx2.AsyncHTTPTransport = httpx2_mod.AsyncHTTPTransport(
        verify=ssl_ctx,
        limits=limits,
        proxy=proxy,
        retries=0,
        socket_options=_KEEPALIVE_SOCKET_OPTIONS,
    )
    return transport


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
        base_init: Any = super().init_poolmanager
        base_init(*args, **kwargs)

    @override
    def proxy_manager_for(self, proxy: str, **proxy_kwargs: Any) -> Any:
        """Ensure proxy connections also strictly enforce TLS 1.2+ and TCP keep-alive.

        Returns:
            Any: The proxy manager instance.
        """
        proxy_kwargs["ssl_context"] = self._ssl_context
        proxy_kwargs.setdefault("socket_options", _KEEPALIVE_SOCKET_OPTIONS)
        base_proxy: Any = super().proxy_manager_for
        return base_proxy(proxy, **proxy_kwargs)

    @override
    def cert_verify(self, conn: Any, url: str, verify: Any, cert: CertConfig) -> None:
        """Enforce strict TLS verification and isolate per-call CA/client-cert SSL contexts."""
        resolved = resolve_tls_verify(verify)
        base_verify: Any = super().cert_verify
        base_verify(conn, url, resolved, cert)
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

    def __init__(self, auth_tuple: object) -> None:
        """Initialize with API credentials and pre-compute Basic Auth header."""
        __tracebackhide__ = True
        if not isinstance(auth_tuple, tuple) or len(auth_tuple) != 2:
            msg = "auth_tuple must be a 2-tuple of (api_key, api_secret)"
            raise ValueError(msg)
        api_key, api_secret = auth_tuple
        if not isinstance(api_key, str) or not isinstance(api_secret, str):
            msg = "API credentials must be strings"
            raise TypeError(msg)
        for val in (api_key, api_secret):
            if any(ord(ch) < 32 or ord(ch) == 127 for ch in val):
                msg = "API credentials contain forbidden control characters or CRLF (CWE-113)"
                raise ValueError(msg)
        self._api_key = api_key
        self._api_secret = api_secret
        try:
            auth_bytes = f"{self._api_key}:{self._api_secret}".encode("latin1")
        except UnicodeEncodeError as e:
            msg = "API credentials must contain valid Latin-1 characters (RFC 7617 Basic Auth)."
            raise ValueError(msg) from e
        self._auth_header = "Basic " + base64.b64encode(auth_bytes).decode("ascii")

    @property
    def auth_header(self) -> str:
        """The pre-encoded Basic Authorization header value.

        Returns:
            str: Pre-computed Basic Authorization header string.
        """
        return self._auth_header

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
        _ = index
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
