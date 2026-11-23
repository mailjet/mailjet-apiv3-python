"""Regression tests locking v1.9.1 backward-compatible submodule, mock, and subclass contracts for v1.10.0."""

from __future__ import annotations

import asyncio
import importlib
import json
import logging
import subprocess
import sys
import warnings
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests

from mailjet_rest.client import AsyncClient, Client, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint


def test_pep562_lazy_submodules_resolve_without_eager_cold_boot() -> None:
    """v1.9.1 contract (#BC-1): `import mailjet_rest; mailjet_rest.<submod>` works lazily without cold-boot bloat."""
    probe = (
        "import json, sys, types, mailjet_rest; "
        "heavy = ('requests', 'urllib3', 'ssl', 'html.parser', 'difflib', 'mimetypes', 'httpx2', 'httpcore2', 'dataclasses'); "
        "before = [m for m in heavy if m in sys.modules]; "
        "submods = ('client', 'config', 'endpoint', 'errors', 'routes', 'types', 'utils', 'builders', 'testing', 'webhooks'); "
        "resolved = {name: isinstance(getattr(mailjet_rest, name), types.ModuleType) for name in submods}; "
        "ver_ok = callable(mailjet_rest.utils.version.get_version); "
        "print(json.dumps({'before': before, 'resolved': resolved, 'ver_ok': ver_ok}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", probe],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    data = json.loads(proc.stdout)
    assert data["before"] == []
    assert all(data["resolved"].values()), f"Unresolved submodules: {data['resolved']}"
    assert data["ver_ok"] is True

    # Exercise in-process PEP 562 __getattr__ resolution on mailjet_rest and mailjet_rest.utils
    mj_pkg = importlib.import_module("mailjet_rest")
    assert mj_pkg.__getattr__("builders").__name__ == "mailjet_rest.builders"
    utils_mod = mj_pkg.__getattr__("utils")
    assert utils_mod.__getattr__("version").__name__ == "mailjet_rest.utils.version"
    with pytest.raises(AttributeError, match="no attribute 'nonexistent_util_xyz'"):
        _ = utils_mod.__getattr__("nonexistent_util_xyz")

    with pytest.raises(AttributeError, match="no attribute 'nonexistent_submodule_xyz'"):
        _ = mj_pkg.nonexistent_submodule_xyz


def test_patch_client_endpoint_and_async_endpoint_intercepts_getattr() -> None:
    """v1.9.1 contract (#BC-2a): unittest.mock.patch('mailjet_rest.client.Endpoint') intercepts route creation."""
    with Client(auth=("pub_key", "priv_key")) as sync_client:
        sentinel_ep = MagicMock(name="SentinelSyncEndpoint")
        with patch("mailjet_rest.client.Endpoint", return_value=sentinel_ep) as mock_ep_cls:
            resolved = sync_client.contact
        assert resolved is sentinel_ep
        mock_ep_cls.assert_called_once_with(client=sync_client, name="contact")

    if _httpx2 is not None:

        async def _check_async() -> None:
            async with AsyncClient(auth=("pub_key", "priv_key")) as async_client:
                sentinel_aep = MagicMock(name="SentinelAsyncEndpoint")
                with patch("mailjet_rest.client.AsyncEndpoint", return_value=sentinel_aep) as mock_aep_cls:
                    resolved_async = async_client.contact
                assert resolved_async is sentinel_aep
                mock_aep_cls.assert_called_once_with(client=async_client, name="contact")

        asyncio.run(_check_async())


def test_client_and_async_client_subclass_and_mock_hook_dispatch(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """v1.9.1 contract (#BC-2b): api_call dispatches through self._handle_api_error/_extract_telemetry/_log_request."""
    resp_200 = requests.Response()
    resp_200.status_code = 200
    resp_200._content = b'{"Count": 0, "Data": []}'

    resp_400 = requests.Response()
    resp_400.status_code = 400
    resp_400._content = b'{"ErrorMessage": "bad input"}'

    # 1. patch.object on Client methods works even at default WARNING log level
    with Client(auth=("pub_key", "priv_key")) as sync_client:
        with (
            patch.object(sync_client.session, "request", return_value=resp_200),
            patch.object(Client, "_extract_telemetry", return_value=(" | Trace: [CustomID=c1]", {})) as mock_tel,
            patch.object(Client, "_log_request") as mock_log,
        ):
            out = sync_client.contact.get()
            assert out.status_code == 200
            mock_tel.assert_called_once()
            mock_log.assert_called_once_with(
                "GET",
                "https://api.mailjet.com/v3/REST/contact",
                resp_200,
                " | Trace: [CustomID=c1]",
            )

        with (
            patch.object(sync_client.session, "request", return_value=resp_400),
            patch.object(Client, "_handle_api_error", side_effect=RuntimeError("custom-sync-handler")) as mock_err,
        ):
            with pytest.raises(RuntimeError, match="custom-sync-handler"):
                sync_client.contact.get()
            mock_err.assert_called_once()

    # 2. Subclass overriding _handle_api_error and _log_request works seamlessly (plus ad-hoc subclass __dict__)
    class InstrumentedClient(Client):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__(*args, **kwargs)
            self.logged_events: list[tuple[str, str, int]] = []

        @staticmethod
        def _log_request(method: str, url: str, response: Any, trace_str: str) -> None:  # type: ignore[override]
            _ = trace_str
            InstrumentedClient._last_seen = (method, url, int(response.status_code))  # type: ignore[attr-defined]

    with InstrumentedClient(auth=("pub_key", "priv_key")) as sub_client:
        sub_client.logged_events.append(("init", "", 0))
        with patch.object(sub_client.session, "request", return_value=resp_200):
            sub_client.contact.get()
        assert getattr(InstrumentedClient, "_last_seen", None) == (
            "GET",
            "https://api.mailjet.com/v3/REST/contact",
            200,
        )

    # 3. Unmodified Client with DEBUG enabled still logs trace cleanly
    with caplog.at_level(logging.DEBUG, logger="mailjet_rest.client"), Client(auth=("pub_key", "priv_key")) as dbg_c:
        with patch.object(dbg_c.session, "request", return_value=resp_200):
            dbg_c.send.create(data={"CustomID": "dbg-trace-1"})
    assert "CustomID=dbg-trace-1" in caplog.text

    # 4. AsyncClient parity for _handle_api_error and _log_request hooks
    if _httpx2 is not None:

        async def _check_async_hooks() -> None:
            def _handler(request: Any) -> Any:
                if request.url.path.endswith("/fail"):
                    return _httpx2.Response(400, json={"ErrorMessage": "async bad"}, request=request)
                return _httpx2.Response(200, json={"Count": 0, "Data": []}, request=request)

            transport = _httpx2.MockTransport(_handler)
            async with AsyncClient(auth=("pub_key", "priv_key"), transport=transport, max_retries=0) as aclient:
                with (
                    patch.object(
                        AsyncClient,
                        "_extract_telemetry",
                        return_value=(" | Trace: [CustomID=ac1]", {}),
                    ) as amock_tel,
                    patch.object(AsyncClient, "_log_request") as amock_log,
                ):
                    aresp = await aclient.contact.get()
                    assert aresp.status_code == 200
                    amock_tel.assert_called_once()
                    amock_log.assert_called_once()

                with patch.object(
                    AsyncClient,
                    "_handle_api_error",
                    side_effect=RuntimeError("custom-async-handler"),
                ) as amock_err:
                    with pytest.raises(RuntimeError, match="custom-async-handler"):
                        await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/fail")
                    amock_err.assert_called_once()

        asyncio.run(_check_async_hooks())


def test_endpoint_check_deprecation_and_v191_module_symbols_preserved() -> None:
    """v1.9.1 contract (#BC-3): BaseEndpoint._check_deprecation and legacy module-level symbols remain available."""
    assert hasattr(Endpoint, "_check_deprecation")
    assert hasattr(AsyncEndpoint, "_check_deprecation")

    with Client(auth=("pub_key", "priv_key")) as sync_client:
        with pytest.warns(DeprecationWarning, match="Endpoint 'newsletter' is deprecated"):
            sync_client.newsletter._check_deprecation()

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always", DeprecationWarning)
            url = sync_client.newsletter._build_url()
        assert url == "https://api.mailjet.com/v3/REST/newsletter"
        dep_msgs = [w for w in recorded if "newsletter" in str(w.message)]
        assert len(dep_msgs) == 1

        with patch.object(Endpoint, "_check_deprecation") as mock_check_dep:
            _ = sync_client.newsletter._build_url()
            mock_check_dep.assert_called_once_with()

    client_mod = importlib.import_module("mailjet_rest.client")
    endpoint_mod = importlib.import_module("mailjet_rest.endpoint")
    guardrails_mod = importlib.import_module("mailjet_rest.utils.guardrails")

    # Module-level v1.9.1 symbols on mailjet_rest.client
    for sym in ("Retry", "_ALLOWED_TRACE_FIELDS", "JitterRetry", "Endpoint", "SecretAuth", "SecureHTTPAdapter"):
        assert hasattr(client_mod, sym), f"Missing v1.9.1 symbol mailjet_rest.client.{sym}"

    # Module-level v1.9.1 symbols on mailjet_rest.endpoint
    for sym in (
        "ROUTE_MAP",
        "DEPRECATION_ADVISORY",
        "SecurityGuard",
        "_JSON_HEADERS",
        "_TEXT_HEADERS",
        "HttpMethod",
        "PayloadType",
        "TimeoutType",
        "json",
        "warnings",
    ):
        assert hasattr(endpoint_mod, sym), f"Missing v1.9.1 symbol mailjet_rest.endpoint.{sym}"
    with pytest.raises(AttributeError, match="no attribute 'nonexistent_ep_attr'"):
        _ = endpoint_mod.__getattr__("nonexistent_ep_attr")

    # Module-level v1.9.1 symbols on mailjet_rest.utils.guardrails (with lazy HTMLParser)
    for sym in ("ValidationError", "HTTPAdapter", "AuthBase", "HTMLParser"):
        assert hasattr(guardrails_mod, sym), f"Missing v1.9.1 symbol mailjet_rest.utils.guardrails.{sym}"
    with pytest.raises(AttributeError, match="no attribute 'nonexistent_gr_attr'"):
        _ = guardrails_mod.__getattr__("nonexistent_gr_attr")
