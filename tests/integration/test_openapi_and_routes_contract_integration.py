"""Offline OpenAPI (v3/v3.1/v4/v1 Passport), 89-route contract, and samples loopback integration tests."""

from __future__ import annotations

import asyncio
import http.server
import importlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse
import warnings
from collections.abc import Generator
from pathlib import Path
from typing import Any, cast

import pytest

from mailjet_rest import (
    AsyncClient,
    Client,
    Config,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    ValidationError,
)
from mailjet_rest.client import _httpx2
from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP


REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).resolve().parent / "fixtures" / "openapi_operations_manifest.json"
HTTP_METHODS = ("get", "post", "put", "patch", "delete")


def _norm_path(path: str) -> str:
    return re.sub(r"\{[^}]+\}", "{param}", path.rstrip("/"))


def _extract_openapi_paths(spec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    extracted: dict[str, dict[str, Any]] = {}
    for raw_path, ops in sorted(spec.get("paths", {}).items()):
        if not isinstance(ops, dict):
            continue
        methods = sorted(m for m in ops if m.lower() in HTTP_METHODS)
        path_params = re.findall(r"\{([^}]+)\}", raw_path)
        deprecated_methods = sorted(
            m for m in methods if isinstance(ops.get(m), dict) and bool(ops[m].get("deprecated"))
        )
        extracted[raw_path] = {
            "methods": methods,
            "path_params": path_params,
            "deprecated_methods": deprecated_methods,
        }
    return extracted


class _ContractHTTPHandler(http.server.BaseHTTPRequestHandler):
    """Thread-safe loopback TLS handler recording wire requests and serving realistic Mailjet JSON/CSV responses."""

    @property
    def _contract_server(self) -> _ContractHTTPSServer:
        return cast("_ContractHTTPSServer", self.server)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _record(self, method: str, body: bytes) -> None:
        with self._contract_server.lock:
            self._contract_server.recorded.append(
                {
                    "method": method,
                    "path": self.path.split("?", 1)[0],
                    "full_path": self.path,
                    "headers": {k.lower(): v for k, v in self.headers.items()},
                    "body": body,
                }
            )

    def _write_bytes(self, status: int, content_type: str, payload: bytes) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        if payload:
            self.wfile.write(payload)

    def _write_json(self, status: int, body: dict[str, Any]) -> None:
        self._write_bytes(status, "application/json", json.dumps(body).encode("utf-8"))

    def _dispatch(self, method: str) -> None:
        body = self._read_body()
        self._record(method, body)
        clean_path = self.path.split("?", 1)[0]
        auth = self.headers.get("Authorization", "")

        if auth in {"Basic aW52YWxpZDppbnZhbGlk", "Bearer invalid_bearer_token"}:
            self._write_json(401, {"StatusCode": 401, "ErrorMessage": "Unauthorized"})
            return

        if clean_path == "/v3/REST/webhook":
            self._write_json(400, {"StatusCode": 400, "ErrorInfo": "", "ErrorMessage": 'Unknown resource: "webhook"'})
            return

        if clean_path == "/v3/REST/messagesentstatistics":
            self._write_json(410, {"StatusCode": 410, "ErrorMessage": "Endpoint retired; use statcounters"})
            return

        if clean_path == "/v3/REST/notfound":
            self._write_json(404, {"ErrorMessage": "Object not found"})
            return

        if clean_path == "/v3.1/send" and method == "POST":
            self._write_json(200, {"Messages": [{"Status": "success", "To": [{"Email": "passenger@example.com"}]}]})
            return

        if clean_path == "/v3/send" and method == "POST":
            self._write_json(200, {"Sent": [{"Email": "passenger@example.com", "MessageID": 1001}]})
            return

        if "/CSVError/text:csv" in clean_path and method == "GET":
            self._write_bytes(200, "text/csv", b"email,error\n")
            return

        if "/CSVData/text:plain" in clean_path:
            if method == "POST":
                self._write_json(200, {"ID": 789, "Count": 1})
            else:
                self._write_bytes(200, "text/plain", b"email,first_name\ntest@example.com,Test\n")
            return

        if method == "POST" and clean_path.endswith("/contents/publish"):
            self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 123}]})
            return

        if method == "POST" and clean_path.endswith(("/contents/lock", "/contents/unlock")):
            self._write_bytes(204, "application/json", b"")
            return

        if method == "DELETE":
            self._write_bytes(204, "application/json", b"")
            return

        if method == "POST":
            self._write_json(
                201,
                {
                    "Count": 1,
                    "Total": 1,
                    "Data": [
                        {
                            "ID": 123,
                            "JobID": 456,
                            "AccessToken": "loopback_demo_tok",  # pragma: allowlist secret
                            "Email": "loopback@example.com",
                        }
                    ],
                },
            )
            return

        self._write_json(
            200,
            {
                "Count": 1,
                "Total": 1,
                "Data": [{"ID": 123, "Email": "loopback@example.com", "Name": "Loopback"}],
            },
        )

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def do_PUT(self) -> None:
        self._dispatch("PUT")

    def do_PATCH(self) -> None:
        self._dispatch("PATCH")

    def do_DELETE(self) -> None:
        self._dispatch("DELETE")


class _ContractHTTPSServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address, _ContractHTTPHandler)
        self.lock = threading.Lock()
        self.recorded: list[dict[str, Any]] = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


def _generate_cert(cert_dir: Path, name: str) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary not available for loopback contract test")
    assert openssl is not None
    cert_path = cert_dir / f"{name}.pem"
    key_path = cert_dir / f"{name}.key"
    subprocess.run(
        [
            openssl,
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            str(key_path),
            "-out",
            str(cert_path),
            "-days",
            "1",
            "-nodes",
            "-subj",
            "/CN=localhost",
            "-addext",
            "subjectAltName=DNS:localhost,IP:127.0.0.1",
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=20,
    )
    return cert_path, key_path


@pytest.fixture(scope="module")
def contract_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback TLS 1.2+ server for OpenAPI and 89-route contract checks."""
    cert_dir = tmp_path_factory.mktemp("contract_tls")
    cert_path, key_path = _generate_cert(cert_dir, "contract_server")
    server = _ContractHTTPSServer(("localhost", 0), cert_path, key_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {"url": f"https://localhost:{port}/", "ca_path": cert_path, "server": server}
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _load_manifest() -> dict[str, Any]:
    return cast("dict[str, Any]", json.loads(MANIFEST_PATH.read_text(encoding="utf-8")))


def _build_route_call_spec(route_name: str, contract: dict[str, Any]) -> dict[str, Any]:
    path_tpl: str = contract["path"]
    version = contract["version"] or "v3"
    kwargs: dict[str, Any] = {}
    formatted_path = path_tpl
    if "{id}" in formatted_path:
        kwargs["id"] = 123
        formatted_path = formatted_path.replace("{id}", "123")
    if "{action_id}" in formatted_path:
        act_val = "image:png" if "images" in route_name else "P"
        kwargs["action_id"] = act_val
        encoded_act = urllib.parse.quote(act_val, safe="")
        formatted_path = formatted_path.replace("{action_id}", encoded_act)

    methods: list[str] = contract["supported_methods"]
    if "get" in methods:
        action = "get"
    elif "get(id)" in methods:
        action = "get"
        if "id" not in kwargs:
            kwargs["id"] = 123
            formatted_path = f"{formatted_path}/123"
    elif "post" in methods:
        action = "create"
    elif "put" in methods:
        action = "update"
    elif "put(id)" in methods:
        action = "update"
        if "id" not in kwargs:
            kwargs["id"] = 123
            formatted_path = f"{formatted_path}/123"
    else:
        action = "delete"
        if "id" not in kwargs:
            kwargs["id"] = 123
            formatted_path = f"{formatted_path}/123"

    expected_http_method = {"get": "GET", "create": "POST", "update": "PUT", "delete": "DELETE"}[action]
    expected_wire_path = f"/{version}/{formatted_path}"
    return {
        "action": action,
        "kwargs": kwargs,
        "expected_method": expected_http_method,
        "expected_path": expected_wire_path,
        "effective_version": version,
    }


def test_route_map_deprecation_and_openapi_parity() -> None:
    """Verify ROUTE_MAP (89), DEPRECATION_ADVISORY (19), and OpenAPI manifests (99 + 15) stay synchronized."""
    manifest = _load_manifest()
    assert len(ROUTE_MAP) == manifest["route_map_count"] == 89
    assert set(ROUTE_MAP) == set(manifest["route_contracts"])
    assert len(DEPRECATION_ADVISORY) == manifest["deprecation_advisory_count"] == 19
    assert set(DEPRECATION_ADVISORY).issubset(ROUTE_MAP)
    assert manifest["openapi_mailjet_count"] == 99
    assert manifest["openapi_passport_count"] == 15

    # If external release-docs OpenAPI specs are available on the workstation, verify zero drift.
    candidate_dirs = []
    if env_dir := os.environ.get("MAILJET_OPENAPI_DIR"):
        candidate_dirs.append(Path(env_dir))
    candidate_dirs.append(REPO_ROOT.parent / "mailjet_docs" / "release-docs-mailjet-rest")

    for spec_dir in candidate_dirs:
        mj_file = spec_dir / "openapi-mailjet.json"
        pp_file = spec_dir / "openapi-passport.json"
        if mj_file.is_file() and pp_file.is_file():
            live_mj = _extract_openapi_paths(json.loads(mj_file.read_text(encoding="utf-8")))
            live_pp = _extract_openapi_paths(json.loads(pp_file.read_text(encoding="utf-8")))
            assert set(live_mj) == set(manifest["openapi_mailjet_paths"]), "openapi-mailjet.json paths drifted!"
            assert set(live_pp) == set(manifest["openapi_passport_paths"]), "openapi-passport.json paths drifted!"
            for path_key, spec_meta in live_mj.items():
                assert spec_meta["methods"] == manifest["openapi_mailjet_paths"][path_key]["methods"]
            for path_key, spec_meta in live_pp.items():
                assert spec_meta["methods"] == manifest["openapi_passport_paths"][path_key]["methods"]
            break


def test_all_89_routes_sync_and_async_loopback_wire_contract(contract_tls_server: dict[str, Any]) -> None:
    """Exercise all 89 ROUTE_MAP entries over loopback TLS 1.2+ for Sync Client and AsyncClient."""
    manifest = _load_manifest()
    contracts: dict[str, dict[str, Any]] = manifest["route_contracts"]
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    server: _ContractHTTPSServer = contract_tls_server["server"]

    async def _verify_all() -> None:
        with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as sync_client:
            async_ctx: AsyncClient | None = (
                AsyncClient(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0))
                if _httpx2 is not None
                else None
            )
            try:
                for route_name in sorted(ROUTE_MAP):
                    contract = contracts[route_name]
                    spec = _build_route_call_spec(route_name, contract)
                    expected_deprecated = route_name in DEPRECATION_ADVISORY or (
                        spec["effective_version"] == "v3" and route_name == "templates"
                    )

                    # 1. Synchronous Client check
                    server.recorded.clear()
                    ep = getattr(sync_client, route_name)
                    fn = getattr(ep, spec["action"])
                    call_kwargs = dict(spec["kwargs"])
                    if spec["action"] in {"create", "update"}:
                        call_kwargs["data"] = {}

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
                    assert (time.monotonic() - t0) < 5.0

                    depr_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
                    if expected_deprecated:
                        assert depr_warnings, f"Expected DeprecationWarning for '{route_name}'"
                    else:
                        assert not depr_warnings, f"Unexpected DeprecationWarning for '{route_name}': {depr_warnings}"

                    wire = server.recorded[-1]
                    assert wire["method"] == spec["expected_method"], f"{route_name}: {wire['method']}"
                    assert wire["path"] == spec["expected_path"], f"{route_name}: {wire['path']}"
                    assert wire["headers"]["content-type"] == contract["default_content_type"]

                    # 2. Asynchronous Client parity check
                    if async_ctx is not None:
                        server.recorded.clear()
                        aep = getattr(async_ctx, route_name)
                        afn = getattr(aep, spec["action"])
                        with warnings.catch_warnings(record=True) as acaught:
                            warnings.simplefilter("always")
                            if route_name == "webhook":
                                with pytest.raises(ValidationError):
                                    await afn(**call_kwargs)
                            elif route_name == "messagesentstatistics":
                                with pytest.raises(MailjetApiError) as aexc_g:
                                    await afn(**call_kwargs)
                                assert aexc_g.value.status_code == 410
                            else:
                                aresp = await afn(**call_kwargs)
                                assert aresp.status_code in {200, 201, 204}

                        adepr = [w for w in acaught if issubclass(w.category, DeprecationWarning)]
                        assert bool(adepr) == expected_deprecated, f"Async deprecation mismatch for {route_name}"
                        awire = server.recorded[-1]
                        assert awire["method"] == spec["expected_method"]
                        assert awire["path"] == spec["expected_path"]
                        assert awire["headers"]["content-type"] == contract["default_content_type"]
            finally:
                if async_ctx is not None:
                    await async_ctx.close()

    asyncio.run(_verify_all())


def _select_preferred_route_for_openapi_path(
    openapi_path: str, contracts: dict[str, dict[str, Any]]
) -> tuple[str, dict[str, Any]]:
    candidates = [(name, c) for name, c in contracts.items() if openapi_path in c["openapi_paths"]]
    assert candidates, f"OpenAPI path has no mapped SDK route: {openapi_path}"
    # Prefer non-deprecated canonical routes and version-pinned v1 routes over v3 fallback aliases.
    candidates.sort(
        key=lambda item: (
            item[1]["deprecated_replacement"] is not None,
            openapi_path.startswith("/v1/") and item[1]["version"] != "v1",
            item[0],
        )
    )
    return candidates[0]


def test_all_114_openapi_paths_and_methods_mapped_to_sdk_calls(contract_tls_server: dict[str, Any]) -> None:
    """Verify every path + HTTP method across openapi-mailjet.json (99) and openapi-passport.json (15) resolves cleanly."""
    manifest = _load_manifest()
    contracts: dict[str, dict[str, Any]] = manifest["route_contracts"]
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]
    server: _ContractHTTPSServer = contract_tls_server["server"]

    all_specs: list[tuple[str, list[str]]] = [
        *[(p, meta["methods"]) for p, meta in manifest["openapi_mailjet_paths"].items()],
        *[(p, meta["methods"]) for p, meta in manifest["openapi_passport_paths"].items()],
    ]
    assert len(all_specs) == 114

    executed_operations = 0
    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        for openapi_path, methods in all_specs:
            route_name, contract = _select_preferred_route_for_openapi_path(openapi_path, contracts)
            route_tpl = contract["path"]
            oa_params = re.findall(r"\{[^}]+\}", openapi_path)

            kwargs: dict[str, Any] = {}
            if "{id}" in route_tpl:
                kwargs["id"] = 123
                if "{action_id}" in route_tpl:
                    kwargs["action_id"] = "image:png" if "images" in openapi_path else "P"
                elif len(oa_params) >= 2:
                    kwargs["action_id"] = 456
            elif len(oa_params) == 1:
                kwargs["id"] = 123

            method_map = {"get": "get", "post": "create", "put": "update", "delete": "delete"}
            for http_method in methods:
                server.recorded.clear()
                sdk_method_name = method_map[http_method]
                call_kwargs = dict(kwargs)
                if sdk_method_name in {"create", "update"}:
                    call_kwargs["data"] = {}
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", DeprecationWarning)
                    resp = getattr(getattr(client, route_name), sdk_method_name)(**call_kwargs)
                assert resp.status_code in {200, 201, 204}
                wire = server.recorded[-1]
                assert wire["method"] == http_method.upper()
                normalized_wire_path = re.sub(r"/(?:123|456|P|image%3Apng)(?=/|$)", "/{param}", wire["path"])
                assert normalized_wire_path == _norm_path(openapi_path), (
                    f"{openapi_path} via {route_name}.{sdk_method_name} produced {wire['path']}"
                )
                executed_operations += 1

    expected_ops = sum(len(m) for _, m in all_specs)
    assert executed_operations == expected_ops
    assert executed_operations >= 170


def test_samples_public_helpers_against_loopback_contract(
    contract_tls_server: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """Import public helpers from samples/ and execute them against the loopback TLS contract server."""
    monkeypatch.chdir(tmp_path)
    monkeypatch.syspath_prepend(str(REPO_ROOT))

    account_settings_sample = importlib.import_module("samples.account_settings_sample")
    batch_sample = importlib.import_module("samples.batch_sample")
    campaign_sample = importlib.import_module("samples.campaign_sample")
    contacts_sample = importlib.import_module("samples.contacts_sample")
    content_api_sample = importlib.import_module("samples.content_api_sample")
    email_template_sample = importlib.import_module("samples.email_template_sample")
    getting_started_sample = importlib.import_module("samples.getting_started_sample")
    messages_sample = importlib.import_module("samples.messages_sample")
    parse_api_sample = importlib.import_module("samples.parse_api_sample")
    segments_sample = importlib.import_module("samples.segments_sample")
    sender_and_domain_samples = importlib.import_module("samples.sender_and_domain_samples")
    statistic_sample = importlib.import_module("samples.statistic_sample")
    webhooks_sample = importlib.import_module("samples.webhooks_sample")

    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]

    with (
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v3", max_retries=0)) as c30,
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v3.1", max_retries=0)) as c31,
        Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, version="v1", max_retries=0)) as c10,
    ):
        assert account_settings_sample.list_api_keys(client=c30).status_code == 200
        assert account_settings_sample.list_api_key_access(client=c30).status_code == 200
        assert account_settings_sample.get_my_profile(client=c30).status_code == 200
        assert account_settings_sample.get_user(client=c30).status_code == 200

        assert batch_sample.send_batch_payload(client=c30).status_code == 201
        assert batch_sample.list_batch_jobs(limit=1, client=c30).status_code == 200
        assert batch_sample.get_batch_job(job_id=123, client=c30).status_code == 200
        assert batch_sample.get_batch_job_csv_error(job_id=123, client=c30).status_code == 200

        assert campaign_sample.create_a_campaign_draft(client=c30).status_code == 201
        assert campaign_sample.by_adding_custom_content(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.schedule_the_campaign(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.send_the_campaign_right_away(draft_id=123, client=c30).status_code == 201
        assert campaign_sample.api_call_requirements(client=c31).status_code == 200

        assert contacts_sample.create_a_contact(client=c30).status_code == 201
        assert contacts_sample.edit_contact_data(client=c30).status_code == 200
        assert contacts_sample.upload_the_csv(list_id=123, client=c30).status_code == 200
        assert contacts_sample.gdpr_delete_contact(contact_id=123, client=c30).status_code == 204
        assert contacts_sample.list_contactslist_signup_requests(client=c30).status_code == 200
        assert contacts_sample.verify_contactslist(list_id=123, client=c30).status_code == 201

        assert content_api_sample.generate_token(client=c10).status_code == 201
        assert content_api_sample.upload_image(client=c10).status_code == 201
        assert content_api_sample.list_v1_templates(client=c10).status_code == 200
        assert content_api_sample.publish_template_contents(template_id=123, client=c10).status_code == 200
        assert content_api_sample.unlock_template_contents(template_id=123, client=c10).status_code == 204
        assert content_api_sample.get_image_by_type(image_id=123, client=c10).status_code == 200

        assert email_template_sample.create_a_template(client=c30).status_code == 201
        assert email_template_sample.create_a_template_detailcontent(template_id=123, client=c30).status_code == 201
        assert email_template_sample.use_templates_with_send_api(client=c31).status_code == 200

        assert getting_started_sample.send_messages(client=c31).status_code == 200
        assert getting_started_sample.send_messages_with_builder(client=c31).status_code == 200
        assert getting_started_sample.retrieve_statistic(client=c30).status_code == 200

        assert messages_sample.list_messages(client=c30).status_code == 200
        assert messages_sample.get_message(message_id=123, client=c30).status_code == 200
        assert messages_sample.get_message_history(message_id=123, client=c30).status_code == 200
        assert messages_sample.get_message_information(message_id=123, client=c30).status_code == 200
        assert messages_sample.list_message_states(client=c30).status_code == 200

        assert parse_api_sample.basic_setup(client=c30).status_code in {200, 201}
        assert segments_sample.create_your_segment(client=c30).status_code == 201
        assert segments_sample.create_a_campaign_with_a_segmentation_filter(123, client=c30).status_code == 201

        assert sender_and_domain_samples.validate_an_entire_domain(dns_id=123, client=c30).status_code == 200
        assert sender_and_domain_samples.do_an_immediate_check_via_a_post(dns_id=123, client=c30).status_code == 201
        assert sender_and_domain_samples.host_a_text_file(sender_id=123, client=c30).status_code == 200
        assert sender_and_domain_samples.validation_by_doing_a_post(sender_id=123, client=c30).status_code == 201
        assert sender_and_domain_samples.list_metasenders(client=c30).status_code == 200

        assert statistic_sample.event_based_vs_message_based_stats_timing(client=c30).status_code == 200
        assert statistic_sample.view_the_spread_of_events_over_time(client=c30).status_code == 200
        assert statistic_sample.statistics_for_specific_recipient(client=c30).status_code == 200
        assert statistic_sample.stats_for_clicked_links(client=c30).status_code == 200
        assert statistic_sample.mailbox_provider_statistics(client=c30).status_code == 200
        assert statistic_sample.geographical_statistics(client=c30).status_code == 200
        assert statistic_sample.campaign_overview(client=c30).status_code == 200
        assert statistic_sample.list_recipient_statistics(client=c30).status_code == 200
        assert statistic_sample.top_links_clicked(client=c30).status_code == 200
        assert statistic_sample.user_agent_statistics(client=c30).status_code == 200

        assert webhooks_sample.verify_webhook_demo() is True
        assert webhooks_sample.list_webhooks(client=c30).status_code == 200
        assert webhooks_sample.setup_webhook(client=c30).status_code == 201
        assert webhooks_sample.get_webhook(123, client=c30).status_code == 200
        assert webhooks_sample.update_webhook(123, client=c30).status_code == 200
        assert webhooks_sample.delete_webhook(123, client=c30).status_code == 204


def test_negative_auth_and_retired_error_envelope_contracts(contract_tls_server: dict[str, Any]) -> None:
    """Verify negative 400/401/404/410 wire contracts, TLS CA enforcement, and invalid Basic/Bearer auth."""
    url: str = contract_tls_server["url"]
    ca_path: Path = contract_tls_server["ca_path"]

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
