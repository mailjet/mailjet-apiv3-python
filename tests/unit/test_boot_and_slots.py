"""Unit tests for Wave 3: PEP 562 lazy boot, __slots__, SSL context cache, keep-alive, and warn_unclosed."""

from __future__ import annotations

import gc
import json
import logging
import os
import socket
import ssl
import subprocess
import sys
import warnings
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest
import requests

from mailjet_rest.builders import ChunkedStreamer
from mailjet_rest.client import Client, Config
from mailjet_rest.utils.guardrails import RedactingFilter, SecretAuth, SecureHTTPAdapter, SecurityGuard
from mailjet_rest.utils.transport_security import _cached_ssl_context, get_secure_ssl_context


def test_pep562_lazy_top_level_import_isolation() -> None:
    """Importing mailjet_rest does not eagerly load heavy transport or parser modules."""
    code = (
        "import json, sys, mailjet_rest; "
        "heavy = ('requests', 'urllib3', 'ssl', 'html.parser', 'difflib', 'mimetypes'); "
        "loaded = [m for m in heavy if m in sys.modules]; "
        "print(json.dumps({'loaded': loaded, 'has_client': 'Client' in dir(mailjet_rest)}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    payload = json.loads(proc.stdout)
    assert payload["loaded"] == []
    assert payload["has_client"] is True


def test_package_lazy_exports_and_missing_attr() -> None:
    """Top-level PEP 562 exposes Client, Config, __version__ and rejects unknown attributes."""
    import mailjet_rest  # ruff: ignore[import-outside-top-level]

    assert mailjet_rest.Client is Client
    assert mailjet_rest.Config is Config
    assert isinstance(mailjet_rest.__version__, str)
    assert "Client" in dir(mailjet_rest)
    assert "__version__" in dir(mailjet_rest)

    with pytest.raises(AttributeError, match="no attribute"):
        _ = mailjet_rest.non_existent_symbol_xyz  # type: ignore[attr-defined]


def test_slots_enforced_and_secret_auth_unslotted() -> None:
    """Client, ChunkedStreamer, and SecurityGuard use __slots__; SecretAuth stays unslotted."""
    client = Client(auth=("api_key_value", "api_secret_value"))
    try:
        assert not hasattr(client, "__dict__")
        assert not hasattr(ChunkedStreamer(), "__dict__")
        assert not hasattr(SecurityGuard(), "__dict__")
        # SecretAuth inherits from requests.auth.AuthBase (unslotted in 1.x)
        assert isinstance(client.auth, SecretAuth)
        assert hasattr(client.auth, "__dict__")
    finally:
        client.close()


def test_lazy_session_and_pool_configuration() -> None:
    """Client defers session creation until first use and applies Config pool sizes."""
    cfg = Config(pool_connections=12, pool_maxsize=24)
    with Client(auth=("api_key_value", "api_secret_value"), config=cfg) as client:
        assert client._session is None
        _ = client.contact
        assert client._session is None

        session = client.session
        assert client._session is session
        adapter = session.adapters["https://"]
        assert isinstance(adapter, SecureHTTPAdapter)
        pool_kw = adapter.poolmanager.connection_pool_kw
        sock_opts = pool_kw.get("socket_options", ())
        assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in sock_opts

        proxy_mgr = adapter.proxy_manager_for("http://127.0.0.1:8080")
        assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in proxy_mgr.connection_pool_kw.get("socket_options", ())


def test_config_pool_and_warn_unclosed_validation() -> None:
    """Config validates pool_connections, pool_maxsize, and warn_unclosed strictly."""
    with pytest.raises(ValueError, match="pool_connections"):
        Config(pool_connections=0)
    with pytest.raises(ValueError, match="pool_maxsize"):
        Config(pool_maxsize=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="warn_unclosed"):
        Config(warn_unclosed="yes")  # type: ignore[arg-type]


def test_ssl_context_cache_and_rotation_invalidation(tmp_path: Path) -> None:
    """get_secure_ssl_context caches identical inputs and reloads when CA file changes."""
    ca_file = tmp_path / "ca.pem"
    ca_file.write_text("dummy-ca-v1", encoding="utf-8")

    fake_ctx_1 = MagicMock(spec=ssl.SSLContext)
    fake_ctx_2 = MagicMock(spec=ssl.SSLContext)
    _cached_ssl_context.cache_clear()

    with patch("ssl.create_default_context", side_effect=[fake_ctx_1, fake_ctx_2]) as mock_ctx:
        ctx_a = get_secure_ssl_context(str(ca_file))
        ctx_b = get_secure_ssl_context(str(ca_file))
        assert ctx_a is fake_ctx_1
        assert ctx_b is fake_ctx_1
        assert mock_ctx.call_count == 1

        # Simulate rotated CA bundle with different size and mtime
        ca_file.write_text("dummy-ca-rotated-v2-longer", encoding="utf-8")
        st = ca_file.stat()
        os.utime(ca_file, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000))

        ctx_c = get_secure_ssl_context(str(ca_file))
        assert ctx_c is fake_ctx_2
        assert mock_ctx.call_count == 2

    _cached_ssl_context.cache_clear()


def test_secret_auth_precomputes_authorization_header() -> None:
    """SecretAuth pre-computes Basic Authorization header in __init__."""
    auth = SecretAuth(("my_key", "my_secret"))
    assert auth._auth_header.startswith("Basic ")
    req = requests.Request("GET", "https://api.mailjet.com/v3/REST/contact").prepare()
    auth(req)
    assert req.headers["Authorization"] == auth._auth_header


def test_redacting_filter_fast_path_and_secret_scrubbing() -> None:
    """RedactingFilter skips regex compilation on clean messages and scrubs secrets when present."""
    flt = RedactingFilter()
    clean_record = logging.LogRecord("mailjet_rest", logging.INFO, "", 0, "Sent campaign batch 42", (), None)

    with patch("mailjet_rest.utils.guardrails._get_secret_pattern", side_effect=AssertionError("should skip regex")):
        assert flt.filter(clean_record) is True
    assert clean_record.msg == "Sent campaign batch 42"

    secret_record = logging.LogRecord(
        "mailjet_rest",
        logging.INFO,
        "",
        0,
        "Using Authorization: Bearer supersecret99",
        (),
        None,
    )
    assert flt.filter(secret_record) is True
    assert "supersecret99" not in str(secret_record.msg)
    assert "********" in str(secret_record.msg)


def test_warn_unclosed_opt_in_lifecycle() -> None:
    """ResourceWarning is emitted on GC only when Config.warn_unclosed=True and session was opened."""
    with warnings.catch_warnings(record=True) as quiet_warnings:
        warnings.simplefilter("always", ResourceWarning)
        c_default = Client(auth=("api_key_value", "api_secret_value"))
        _ = c_default.session
        del c_default
        gc.collect()
    assert not [w for w in quiet_warnings if issubclass(w.category, ResourceWarning)]

    with pytest.warns(ResourceWarning, match="Unclosed Mailjet Client session"):
        c_warn = Client(auth=("api_key_value", "api_secret_value"), warn_unclosed=True)
        _ = c_warn.session
        del c_warn
        gc.collect()
