"""Loopback TLS 1.2+ contract server and shared OpenAPI/ROUTE_MAP assertion helpers."""

from __future__ import annotations

import http.server
import json
import re
import ssl
import threading
import urllib.parse
from typing import TYPE_CHECKING, Any, cast

import warnings

from mailjet_rest.routes import DEPRECATION_ADVISORY
from tests.integration.conftest import HTTP_METHODS, generate_loopback_tls_cert


if TYPE_CHECKING:
    from collections.abc import Generator
    from pathlib import Path

    import pytest


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
    """Loopback TLS 1.2+ HTTP server recording wire requests."""

    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address, _ContractHTTPHandler)
        self.lock = threading.Lock()
        self.recorded: list[dict[str, Any]] = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)

    def clear_recorded(self) -> None:
        """Clear all recorded wire requests under the server lock."""
        with self.lock:
            self.recorded.clear()

    def last_recorded(self) -> dict[str, Any]:
        """Return a copy of the most recently recorded wire request under the server lock."""
        with self.lock:
            return dict(self.recorded[-1])

    def snapshot_recorded(self) -> list[dict[str, Any]]:
        """Return a shallow snapshot of all recorded wire requests under the server lock."""
        with self.lock:
            return list(self.recorded)


def build_contract_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback TLS 1.2+ server with valid and untrusted CA certs."""
    cert_dir = tmp_path_factory.mktemp("contract_tls")
    cert_path, key_path = generate_loopback_tls_cert(cert_dir, "contract_server")
    wrong_ca_path, _ = generate_loopback_tls_cert(cert_dir, "wrong_ca")
    server = _ContractHTTPSServer(("localhost", 0), cert_path, key_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"https://localhost:{port}/",
            "ca_path": cert_path,
            "wrong_ca_path": wrong_ca_path,
            "server": server,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


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


def prepare_route_call(route_name: str, contract: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], bool]:
    """Build call specification, kwargs, and deprecation expectation for one ROUTE_MAP entry."""
    spec = _build_route_call_spec(route_name, contract)
    expected_deprecated = route_name in DEPRECATION_ADVISORY or (
        spec["effective_version"] == "v3" and route_name == "templates"
    )
    call_kwargs = dict(spec["kwargs"])
    if spec["action"] in {"create", "update"}:
        call_kwargs["data"] = {}
    return spec, call_kwargs, expected_deprecated


def assert_route_wire_and_deprecation(
    route_name: str,
    contract: dict[str, Any],
    spec: dict[str, Any],
    *,
    expected_deprecated: bool,
    caught: list[warnings.WarningMessage],
    wire: dict[str, Any],
    elapsed_s: float,
) -> None:
    """Assert SLA latency, DeprecationWarning contract, and wire method/path/Content-Type."""
    assert elapsed_s < 5.0
    depr_warnings = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    if expected_deprecated:
        assert depr_warnings, f"Expected DeprecationWarning for '{route_name}'"
    else:
        assert not depr_warnings, f"Unexpected DeprecationWarning for '{route_name}': {depr_warnings}"

    assert wire["method"] == spec["expected_method"], f"{route_name}: {wire['method']}"
    assert wire["path"] == spec["expected_path"], f"{route_name}: {wire['path']}"
    assert wire["headers"]["content-type"] == contract["default_content_type"]


def build_openapi_operation_plan(manifest: dict[str, Any]) -> list[tuple[str, str, str, str, dict[str, Any]]]:
    """Build the ordered list of all OpenAPI path + HTTP method operations mapped to SDK calls."""
    contracts: dict[str, dict[str, Any]] = manifest["route_contracts"]
    all_specs: list[tuple[str, list[str]]] = [
        *[(p, meta["methods"]) for p, meta in manifest["openapi_mailjet_paths"].items()],
        *[(p, meta["methods"]) for p, meta in manifest["openapi_passport_paths"].items()],
    ]
    assert len(all_specs) == 114

    method_map = {"get": "get", "post": "create", "put": "update", "delete": "delete"}
    operations: list[tuple[str, str, str, str, dict[str, Any]]] = []
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

        for http_method in methods:
            sdk_method_name = method_map[http_method]
            call_kwargs = dict(kwargs)
            if sdk_method_name in {"create", "update"}:
                call_kwargs["data"] = {}
            operations.append((openapi_path, http_method, route_name, sdk_method_name, call_kwargs))

    expected_ops = sum(len(m) for _, m in all_specs)
    assert len(operations) == expected_ops
    assert len(operations) >= 170
    return operations


def assert_openapi_wire_match(
    openapi_path: str,
    http_method: str,
    route_name: str,
    sdk_method_name: str,
    wire: dict[str, Any],
) -> None:
    """Verify the loopback wire method and normalized path match the OpenAPI path template."""
    assert wire["method"] == http_method.upper()
    normalized_wire_path = re.sub(r"/(?:123|456|P|image%3Apng)(?=/|$)", "/{param}", wire["path"])
    assert normalized_wire_path == _norm_path(openapi_path), (
        f"{openapi_path} via {route_name}.{sdk_method_name} produced {wire['path']}"
    )
