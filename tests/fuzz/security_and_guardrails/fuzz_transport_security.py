#!/usr/bin/env python3
"""Atheris fuzzing target for transport TLS resolution, httpx2 timeout coercion, and SecretAuth."""

from __future__ import annotations

import atexit
import logging
import os
import shutil
import ssl
import tempfile
import sys
import warnings
from pathlib import Path
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.client import _httpx2 as httpx2
    from mailjet_rest.utils.transport_security import (
        SecretAuth,
        SecureHTTPAdapter,
        coerce_httpx2_timeout,
        get_secure_ssl_context,
        resolve_tls_verify,
    )


_FUZZ_TMP_DIR = Path(tempfile.mkdtemp(prefix="mj_fuzz_ts_"))
atexit.register(shutil.rmtree, _FUZZ_TMP_DIR, True)
_DUMMY_CA_FILE = _FUZZ_TMP_DIR / "dummy_ca.pem"
_DUMMY_CA_FILE.write_text("dummy-ca-bundle-placeholder\n", encoding="utf-8")


class _FuzzStrPathLike:
    """Slotted os.PathLike[str] test double."""

    __slots__ = ("_path",)

    def __init__(self, path: str) -> None:
        self._path = path

    def __fspath__(self) -> str:
        return self._path


class _FuzzBytesPathLike:
    """Slotted os.PathLike[bytes] test double."""

    __slots__ = ("_path",)

    def __init__(self, path: bytes) -> None:
        self._path = path

    def __fspath__(self) -> bytes:
        return self._path


class _TimeoutDouble:
    """Minimal httpx2.Timeout double used when optional httpx2 extra is absent."""

    __slots__ = ("connect", "pool", "read", "timeout", "write")

    def __init__(
        self, timeout: float, *, connect: float = 0.0, read: float = 0.0, write: float = 0.0, pool: float = 0.0
    ) -> None:
        self.timeout = timeout
        self.connect = connect
        self.read = read
        self.write = write
        self.pool = pool


class _StubHttpx2Module:
    """Minimal module-like timeout factory fallback."""

    __slots__ = ("Timeout",)

    def __init__(self) -> None:
        self.Timeout = _TimeoutDouble


_STUB_HTTPX2 = _StubHttpx2Module()


class _FakeConn:
    """Minimal urllib3 connection carrier for SecureHTTPAdapter.cert_verify checks."""

    __slots__ = ("ca_cert_dir", "ca_certs", "ssl_context")

    def __init__(self) -> None:
        self.ssl_context: Any = None
        self.ca_certs: Any = "unset"
        self.ca_cert_dir: Any = "unset"


class _FakePreparedRequest:
    """Slotted requests.PreparedRequest stand-in for SecretAuth.__call__."""

    __slots__ = ("headers",)

    def __init__(self) -> None:
        self.headers: dict[str, str] = {}


def _fuzz_resolve_tls_verify(fdp: atheris.FuzzedDataProvider) -> None:
    choice = fdp.ConsumeIntInRange(0, 8)
    if choice in {0, 1}:
        bad_flag: Any = False if choice == 0 else None
        try:
            resolve_tls_verify(bad_flag)
        except ValueError:
            return
        msg = f"resolve_tls_verify({bad_flag!r}) failed to reject disabled TLS verification"
        raise AssertionError(msg)

    if choice == 2:
        if resolve_tls_verify(True) is not True:
            msg = "resolve_tls_verify(True) must return True"
            raise AssertionError(msg)
        return

    if choice == 3:
        resolved = resolve_tls_verify(_FuzzStrPathLike(str(_DUMMY_CA_FILE)))
        if resolved != str(_DUMMY_CA_FILE):
            msg = f"Unexpected CA bundle resolution: {resolved!r}"
            raise AssertionError(msg)
        return

    if choice == 4:
        try:
            resolve_tls_verify(_FuzzBytesPathLike(os.fsencode(_DUMMY_CA_FILE)))
        except TypeError:
            return
        msg = "resolve_tls_verify must reject os.PathLike[bytes]"
        raise AssertionError(msg)

    if choice == 5:
        try:
            resolve_tls_verify(_FUZZ_TMP_DIR)
        except ValueError:
            return
        msg = "resolve_tls_verify must reject directory paths as CA bundles"
        raise AssertionError(msg)

    if choice == 6:
        try:
            resolve_tls_verify("~nonexistent_mj_fuzz_user_99999/ca.pem")
        except ValueError:
            return
        msg = "resolve_tls_verify must reject unresolvable tilde home paths"
        raise AssertionError(msg)

    candidate: Any = fdp.ConsumeUnicodeNoSurrogates(48) if choice == 7 else [1, 2, 3]
    try:
        resolve_tls_verify(candidate)
    except (ValueError, TypeError):
        # Expected rejection for invalid CA path string or non-path type.
        return


def _fuzz_timeout_and_ssl(fdp: atheris.FuzzedDataProvider) -> None:
    target_mod = httpx2 if httpx2 is not None else _STUB_HTTPX2
    t_kind = fdp.ConsumeIntInRange(0, 4)
    if t_kind == 0:
        bool_val = fdp.ConsumeBool()
        out = coerce_httpx2_timeout(target_mod, bool_val)
        if out is not bool_val:
            msg = f"coerce_httpx2_timeout must not coerce bool {bool_val!r} as numeric timeout"
            raise AssertionError(msg)
        return

    if t_kind == 1:
        val: Any = fdp.ConsumeFloatInRange(0.01, 120.0)
    elif t_kind == 2:
        val = (fdp.ConsumeFloatInRange(0.01, 30.0), fdp.ConsumeFloatInRange(0.01, 120.0))
    elif t_kind == 3:
        val = (1.0, 2.0, 3.0)
    else:
        val = fdp.ConsumeUnicodeNoSurrogates(12)

    try:
        coerce_httpx2_timeout(target_mod, val)
    except ValueError:
        # httpx2 may reject non-finite/negative values on construction.
        return

    ssl_ctx = get_secure_ssl_context(None)
    if (
        ssl_ctx.minimum_version < ssl.TLSVersion.TLSv1_2
        or not ssl_ctx.check_hostname
        or ssl_ctx.verify_mode != ssl.CERT_REQUIRED
    ):
        msg = "Hardened SSLContext invariants violated"
        raise AssertionError(msg)

    adapter = SecureHTTPAdapter()
    conn = _FakeConn()
    try:
        adapter.cert_verify(conn, "https://api.mailjet.com/v3/REST/contact", False, None)
    except ValueError:
        # Expected CWE-295 rejection for verify=False on adapter.cert_verify.
        pass
    else:
        msg = "SecureHTTPAdapter.cert_verify must reject verify=False"
        raise AssertionError(msg)


def _fuzz_secret_auth(fdp: atheris.FuzzedDataProvider) -> None:
    variant = fdp.ConsumeIntInRange(0, 3)
    if variant == 0:
        raw_tuple: Any = tuple(fdp.ConsumeUnicodeNoSurrogates(12) for _ in range(fdp.PickValueInList([0, 1, 3])))
        try:
            SecretAuth(raw_tuple)
        except ValueError:
            return
        msg = f"SecretAuth accepted invalid tuple length {len(raw_tuple)}"
        raise AssertionError(msg)

    if variant == 1:
        raw_tuple = (fdp.ConsumeInt(100), "fuzz_val")
        try:
            SecretAuth(raw_tuple)
        except TypeError:
            return
        msg = "SecretAuth must reject non-string credential tuple items"
        raise AssertionError(msg)

    k = fdp.ConsumeUnicodeNoSurrogates(24) or "fuzz_k"
    v = fdp.ConsumeUnicodeNoSurrogates(24) or "fuzz_v"
    if variant == 2 and fdp.ConsumeBool():
        k = f"{k}\r\n"

    try:
        auth = SecretAuth((k, v))
    except ValueError:
        # Expected rejection for control characters or non-Latin-1 sequences.
        return

    if any(ord(ch) < 32 or ord(ch) == 127 for ch in k + v):
        msg = "SecretAuth accepted control characters"
        raise AssertionError(msg)

    if repr(auth) != "SecretAuth(***REDACTED***)" or str(auth) != "SecretAuth(***REDACTED***)":
        msg = "SecretAuth repr/str failed redaction check"
        raise AssertionError(msg)

    if not (auth == SecretAuth((k, v)) and auth == (k, v)):
        msg = "SecretAuth constant-time equality failed on identical credentials"
        raise AssertionError(msg)

    _ = hash(auth)
    req: Any = _FakePreparedRequest()
    auth(req)
    if not req.headers.get("Authorization", "").startswith("Basic "):
        msg = "SecretAuth.__call__ must populate Basic Authorization header"
        raise AssertionError(msg)

    try:
        _ = auth[0]
    except TypeError:
        # Expected block against credential indexing (CWE-316).
        pass
    else:
        msg = "SecretAuth.__getitem__ must raise TypeError"
        raise AssertionError(msg)

    try:
        iter(auth)
    except TypeError:
        # Expected block against credential iteration (CWE-316).
        return
    msg = "SecretAuth.__iter__ must raise TypeError"
    raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across TLS, timeout coercion, and SecretAuth helpers."""
    if len(data) < 4:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _fuzz_resolve_tls_verify(fdp)
        elif mode == 1:
            _fuzz_timeout_and_ssl(fdp)
        else:
            _fuzz_secret_auth(fdp)
    except (ValueError, TypeError):
        # Expected validation and type rejections on fuzzed transport inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_transport_security: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for Mailjet transport security utilities."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
