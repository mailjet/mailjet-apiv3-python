"""Synchronous Client loopback wire contract tests for all 89 routes and 114 OpenAPI paths."""

from __future__ import annotations

import time
import warnings
from typing import TYPE_CHECKING, Any

import pytest

from mailjet_rest import (
    Client,
    Config,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    ValidationError,
)
from mailjet_rest.routes import ROUTE_MAP
from tests.integration.conftest import load_openapi_manifest
from tests.integration.contracts._server import (
    assert_openapi_wire_match,
    assert_route_wire_and_deprecation,
    build_openapi_operation_plan,
    prepare_route_call,
)


if TYPE_CHECKING:
    from pathlib import Path

    from tests.integration.contracts._server import _ContractHTTPSServer


def test_all_89_routes_loopback_wire_contract(contract_tls_server: dict[str, Any]) -> None:
    """Exercise all 89 ROUTE_MAP entries over loopback TLS 1.2+ using synchronous Client."""
    manifest = load_openapi_manifest()
    contracts: dict[str, dict[str, Any]] = manifest["route_contracts"]
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    server: _ContractHTTPSServer = contract_tls_server["server"]

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        for route_name in sorted(ROUTE_MAP):
            contract = contracts[route_name]
            spec, call_kwargs, expected_deprecated = prepare_route_call(route_name, contract)
            server.clear_recorded()
            fn = getattr(getattr(client, route_name), spec["action"])

            t0 = time.monotonic()
            with warnings.catch_warnings(record=True) as caught:
                warnings.simplefilter("always")
                if route_name == "webhook":
                    with pytest.raises(ValidationError) as exc_v:
                        fn(**call_kwargs)
                    assert exc_v.value.status_code == 400
                elif route_name == "messagesentstatistics":
                    with pytest.raises(MailjetApiError) as exc_g:
                        fn(**call_kwargs)
                    assert exc_g.value.status_code == 410
                else:
                    resp = fn(**call_kwargs)
                    assert resp.status_code in {200, 201, 204}
            elapsed_s = time.monotonic() - t0

            assert_route_wire_and_deprecation(
                route_name,
                contract,
                spec,
                expected_deprecated=expected_deprecated,
                caught=caught,
                wire=server.last_recorded(),
                elapsed_s=elapsed_s,
            )


def test_all_114_openapi_paths_and_methods_mapped_to_sdk_calls(contract_tls_server: dict[str, Any]) -> None:
    """Verify every path + HTTP method across openapi-mailjet.json (99) and openapi-passport.json (15) resolves cleanly."""
    manifest = load_openapi_manifest()
    operations = build_openapi_operation_plan(manifest)
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    server: _ContractHTTPSServer = contract_tls_server["server"]

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        for openapi_path, http_method, route_name, sdk_method_name, call_kwargs in operations:
            server.clear_recorded()
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                resp = getattr(getattr(client, route_name), sdk_method_name)(**call_kwargs)
            assert resp.status_code in {200, 201, 204}
            assert_openapi_wire_match(openapi_path, http_method, route_name, sdk_method_name, server.last_recorded())


def test_negative_auth_and_retired_error_envelope_contracts(contract_tls_server: dict[str, Any]) -> None:
    """Verify negative 400/401/404/410 wire contracts, TLS CA enforcement, and invalid Basic/Bearer auth."""
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    wrong_ca_path: Path = contract_tls_server["wrong_ca_path"]

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=wrong_ca_path, max_retries=0)) as bad_ca:
        with pytest.raises(CriticalApiError):
            bad_ca.contact.get()

    with Client(auth=("invalid", "invalid"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as bad_basic:
        with pytest.raises(MailjetAuthError) as exc_401:
            bad_basic.contact.get()
        assert exc_401.value.status_code == 401

    with Client(
        auth="invalid_bearer_token",
        config=Config(api_url=url, verify=ca_path, version="v1", max_retries=0),
    ) as bad_bearer:
        with pytest.raises(MailjetAuthError) as exc_b401:
            bad_bearer.v1_templates.get()
        assert exc_b401.value.status_code == 401

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as ok_client:
        with pytest.raises(DoesNotExistError) as exc_404:
            ok_client.notfound.get()
        assert exc_404.value.status_code == 404

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            with pytest.raises(ValidationError) as exc_w:
                ok_client.webhook.get()
            assert exc_w.value.status_code == 400
            with pytest.raises(MailjetApiError) as exc_m:
                ok_client.messagesentstatistics.get()
            assert exc_m.value.status_code == 410
