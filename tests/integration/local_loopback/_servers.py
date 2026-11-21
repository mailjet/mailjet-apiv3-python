"""Shared loopback HTTP/HTTPS test servers, TLS helpers, and mock objects for local_loopback suites."""

from __future__ import annotations

import hashlib
import hmac
import http.server
import json
import logging
import socket
import ssl
import threading
from collections.abc import Generator, Iterator, Mapping
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from email.utils import format_datetime
from pathlib import Path
from typing import Any, NamedTuple, cast
from urllib.parse import parse_qs, urlparse

from mailjet_rest import verify_webhook_signature
from mailjet_rest.errors import MAX_ERROR_BODY_CHARS
from tests.integration.conftest import generate_loopback_tls_cert


_WEBHOOK_SECRET = "whsec_local_integration_test_key_0123456789"  # pragma: allowlist secret


def unused_loopback_port() -> int:
    """Bind an ephemeral loopback port and immediately return its port number."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _sign_webhook_payload(
    payload_bytes: bytes,
    secret: str,
    *,
    timestamp_unix: int | None = None,
    signed_timestamp: bool = False,
) -> str:
    mac_input = f"{timestamp_unix}.".encode("ascii") + payload_bytes if signed_timestamp else payload_bytes
    return hmac.new(secret.encode("utf-8"), mac_input, hashlib.sha256).hexdigest()


class _TransportIntegrationHandler(http.server.BaseHTTPRequestHandler):
    """Thread-safe local HTTP/HTTPS Mailjet stub exercising status codes, headers, retries, and pagination."""

    @property
    def _srv(self) -> _BaseRecordingServer:
        return cast("_BaseRecordingServer", self.server)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _write_bytes(
        self,
        status: int,
        raw: bytes,
        *,
        content_type: str | None = "application/json",
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        try:
            self.send_response(status)
            if content_type is not None:
                self.send_header("Content-Type", content_type)
            if status not in {204, 205, 304}:
                self.send_header("Content-Length", str(len(raw)))
            if extra_headers:
                for k, v in extra_headers.items():
                    self.send_header(k, v)
            self.end_headers()
            if raw and status not in {204, 205, 304}:
                self.wfile.write(raw)
        except OSError:
            # Loopback client disconnected early before reading full response.
            pass

    def _write_json(self, status: int, payload: Any, extra_headers: dict[str, str] | None = None) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self._write_bytes(status, encoded, content_type="application/json", extra_headers=extra_headers)

    def _record(self, method: str, body: bytes) -> tuple[str, dict[str, list[str]]]:
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        self._srv.recorded_requests.append(
            {
                "method": method,
                "path": parsed.path,
                "raw_path": self.path,
                "query": query,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )
        return parsed.path, query

    def _handle_contact_get(self, query: dict[str, list[str]]) -> None:
        if query.get("empty_stream") == ["1"]:
            self._write_json(200, {"Count": 0, "Total": 0, "Data": []})
            return
        if query.get("bad_json") == ["1"]:
            self._write_bytes(200, b"not-valid-json", content_type="text/plain")
            return
        if query.get("list_json") == ["1"]:
            self._write_json(200, [1, 2, 3])
            return
        if query.get("no_data") == ["1"]:
            self._write_json(200, {"Count": 0})
            return
        if query.get("bad_data") == ["1"]:
            self._write_json(200, {"Data": "not-a-list"})
            return

        offset = int(query.get("Offset", ["0"])[0])
        limit = int(query.get("Limit", ["10"])[0])
        items = [{"ID": 1}, {"ID": 2}, {"ID": 3}]
        page = items[offset : offset + limit]
        self._write_json(200, {"Count": len(page), "Total": len(items), "Data": page})

    def do_GET(self) -> None:
        body = self._read_body()
        path, query = self._record("GET", body)

        if self.headers.get("Authorization") == "Basic aW52YWxpZDppbnZhbGlk":
            self._write_json(401, {"ErrorMessage": "Invalid credentials"})
            return

        if path == "/v3/REST/apikey":
            if self.headers.get("Authorization") == "Bearer fail_ping":
                self._write_json(503, {"ErrorMessage": "Service unavailable"})
            else:
                self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 1}]})
            return

        if path == "/v3/REST/slow":
            self._srv.shutdown_event.wait(0.25)
            self._write_json(200, {"Count": 0, "Data": []})
            return

        if path == "/v3/REST/flaky503":
            attempt = self._srv.flaky_503_calls
            self._srv.flaky_503_calls += 1
            if attempt == 0:
                self._write_json(503, {"ErrorMessage": "Temporary overload"})
                return
            self._write_json(200, {"Count": 1, "Data": [{"ID": 55}]})
            return

        if path == "/v3/REST/always429":
            self._write_json(429, {"ErrorMessage": "Too many requests"}, extra_headers={"Retry-After": "0"})
            return

        if path == "/v3/REST/forbidden":
            self._write_json(403, {"ErrorMessage": "Forbidden action"})
            return

        if path == "/v3/REST/notfound":
            self._write_json(404, {"ErrorMessage": "Object not found"})
            return

        if path == "/v3/REST/err500":
            self._write_json(500, {"ErrorMessage": "Internal failure"})
            return

        if path == "/v3/REST/badreqlist":
            self._write_json(400, ["list-level-error"])
            return

        if path == "/v3/REST/badreqempty":
            self._write_bytes(400, b"", content_type="text/plain")
            return

        if path == "/v3/REST/badreqbig":
            huge = ("E" * (MAX_ERROR_BODY_CHARS + 500) + "\n\x00tail").encode("utf-8")
            self._write_bytes(400, huge, content_type="text/plain")
            return

        if path == "/v3/REST/badreqinfo":
            self._write_json(400, {"ErrorInfo": "Schema mismatch", "Messages": [{"Errors": []}]})
            return

        if path == "/v3/REST/nocontent":
            self._write_bytes(204, b"", content_type=None)
            return

        if path == "/v3/REST/resetcontent":
            self._write_bytes(205, b"", content_type=None)
            return

        if path == "/v3/REST/notmodified":
            self._write_bytes(304, b"", content_type=None)
            return

        if path == "/v3/REST/redirect":
            self._write_bytes(302, b"", content_type=None, extra_headers={"Location": "https://evil.example/bounce"})
            return

        if path == "/v3/REST/contact":
            self._handle_contact_get(query)
            return

        self._write_json(200, {"Count": 1, "Data": [{"ID": 1}], "path": path, "query": query})

    def do_POST(self) -> None:
        body = self._read_body()
        path, _ = self._record("POST", body)

        if path == "/v3/REST/flaky":
            attempt = self._srv.flaky_calls
            self._srv.flaky_calls += 1
            if attempt < 2:
                retry_after = (
                    format_datetime(datetime.now(timezone.utc) - timedelta(seconds=1), usegmt=True)
                    if self.headers.get("X-Use-Http-Date") == "1"
                    else "0"
                )
                self._write_json(429, {"ErrorMessage": "Rate limit"}, extra_headers={"Retry-After": retry_after})
                return
            self._write_json(
                201,
                {"Count": 1, "Data": [{"ID": 99}], "echo_len": len(body), "body_text": body.decode("utf-8", "replace")},
            )
            return

        if path == "/v3/REST/always429":
            self._write_json(429, {"ErrorMessage": "Rate limited"}, extra_headers={"Retry-After": "0"})
            return

        self._write_json(201, {"Count": 1, "Data": [{"ID": 101}], "path": path, "echo_len": len(body)})

    def do_PUT(self) -> None:
        body = self._read_body()
        path, _ = self._record("PUT", body)
        self._write_json(200, {"Count": 1, "Data": [{"ID": 42}], "path": path})

    def do_PATCH(self) -> None:
        body = self._read_body()
        path, _ = self._record("PATCH", body)
        self._write_json(200, {"Count": 1, "Data": [{"ID": 42, "Patched": True}], "path": path})

    def do_DELETE(self) -> None:
        body = self._read_body()
        self._record("DELETE", body)
        self._write_bytes(204, b"", content_type=None)


class _BaseRecordingServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int]) -> None:
        super().__init__(server_address, _TransportIntegrationHandler)
        self.recorded_requests: list[dict[str, Any]] = []
        self.flaky_calls = 0
        self.flaky_503_calls = 0
        self.shutdown_event = threading.Event()

    def handle_error(self, request: Any, client_address: Any) -> None:
        """Suppress noisy stderr tracebacks when clients abort on intentional timeout tests."""
        _ = (request, client_address)


class _RecordingHTTPSServer(_BaseRecordingServer):
    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


class _IntegrationTLSHandler(http.server.BaseHTTPRequestHandler):
    """Thread-safe local HTTPS stub verifying built payloads, headers, and multipart uploads."""

    @property
    def _tls_server(self) -> _IntegrationHTTPSServer:
        return cast("_IntegrationHTTPSServer", self.server)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _write_json(self, status: int, payload: dict[str, Any]) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def _record(self, method: str, body: bytes) -> None:
        self._tls_server.recorded_requests.append(
            {
                "method": method,
                "path": self.path,
                "headers": {k.lower(): v for k, v in self.headers.items()},
                "body": body,
            }
        )

    def do_GET(self) -> None:
        body = self._read_body()
        self._record("GET", body)
        self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 1}]})

    def do_POST(self) -> None:
        body = self._read_body()
        self._record("POST", body)

        if self.path.startswith("/v3.1/send"):
            parsed = json.loads(body.decode("utf-8"))
            first_msg = parsed["Messages"][0] if parsed.get("Messages") else {}
            custom_id = first_msg.get("CustomID", "")
            if custom_id == "trigger-400":
                self._write_json(
                    400,
                    {"Messages": [{"Errors": [{"ErrorMessage": "Simulated send failure"}]}]},
                )
                return
            self._write_json(
                200,
                {
                    "Messages": [
                        {
                            "Status": "success",
                            "CustomID": custom_id,
                            "To": [
                                {
                                    "Email": "to@example.com",
                                    "MessageUUID": "uuid-loopback-1",
                                    "MessageID": 1001,
                                    "MessageHref": "https://api.mailjet.com/v3/REST/message/1001",
                                }
                            ],
                        }
                    ]
                },
            )
            return

        if self.path.startswith("/v3/REST/template/"):
            parsed = json.loads(body.decode("utf-8"))
            self._write_json(201, {"Count": 1, "Data": [parsed]})
            return

        if self.path.startswith("/v1/data/images"):
            ctype = self.headers.get("Content-Type", "")
            self._write_json(201, {"Count": 1, "Data": [{"ID": "img-1", "content_type": ctype}]})
            return

        self._write_json(201, {"Count": 1, "Data": [{"ID": 100}]})


class _IntegrationHTTPSServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address, _IntegrationTLSHandler)
        self.recorded_requests: list[dict[str, Any]] = []
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


class _WebhookReceiverHandler(http.server.BaseHTTPRequestHandler):
    """Loopback HTTP webhook receiver verifying X-Mailjet-Signature headers."""

    @property
    def _webhook_server(self) -> _WebhookHTTPServer:
        return cast("_WebhookHTTPServer", self.server)

    def log_message(self, format: str, *args: Any) -> None:
        _ = (format, args)

    def _write_json(self, status: int, body: dict[str, Any]) -> None:
        encoded = json.dumps(body).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def do_POST(self) -> None:
        raw_len = self.headers.get("Content-Length", "0") or "0"
        try:
            length = int(raw_len)
        except ValueError:
            self._write_json(400, {"verified": False, "error": "invalid Content-Length"})
            return

        payload_bytes = self.rfile.read(length) if length > 0 else b""
        signature_header = self.headers.get("X-Mailjet-Signature", "")
        raw_timestamp = self.headers.get("X-Mailjet-Timestamp")
        raw_max_age = self.headers.get("X-Max-Age")
        signed_timestamp = self.headers.get("X-Verify-Mode", "raw") == "signed-ts"

        timestamp_unix: int | None = None
        if raw_timestamp is not None:
            try:
                timestamp_unix = int(raw_timestamp)
            except ValueError:
                self._write_json(400, {"verified": False, "error": "invalid X-Mailjet-Timestamp"})
                return

        max_age_seconds = 300
        if raw_max_age is not None:
            try:
                max_age_seconds = int(raw_max_age)
            except ValueError:
                self._write_json(400, {"verified": False, "error": "invalid X-Max-Age"})
                return

        try:
            verified = verify_webhook_signature(
                payload_bytes,
                signature_header,
                self._webhook_server.webhook_secret,
                timestamp_unix=timestamp_unix,
                max_age_seconds=max_age_seconds,
                signed_timestamp=signed_timestamp,
            )
        except (TypeError, ValueError) as exc:
            self._webhook_server.rejected_requests.append({"reason": str(exc), "status": 400})
            self._write_json(400, {"verified": False, "error": str(exc)})
            return

        if verified:
            self._webhook_server.verified_requests.append(
                {
                    "path": self.path,
                    "payload": payload_bytes,
                    "timestamp": timestamp_unix,
                    "signed_timestamp": signed_timestamp,
                }
            )
            self._write_json(200, {"verified": True})
            return

        self._webhook_server.rejected_requests.append({"path": self.path, "payload": payload_bytes, "status": 401})
        self._write_json(401, {"verified": False})


class _WebhookHTTPServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], webhook_secret: str) -> None:
        super().__init__(server_address, _WebhookReceiverHandler)
        self.webhook_secret = webhook_secret
        self.verified_requests: list[dict[str, Any]] = []
        self.rejected_requests: list[dict[str, Any]] = []


class _BytesPathLike:
    def __init__(self, path_bytes: bytes = b"ca.pem") -> None:
        self._path_bytes = path_bytes

    def __fspath__(self) -> bytes:
        return self._path_bytes


class _ListHandler(logging.Handler):
    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)


class _SecretPair(NamedTuple):
    token: str
    note: str


class _ModelDumpObj:
    def model_dump(self) -> dict[str, Any]:
        return {
            "api_key": "secret-key-val",  # pragma: allowlist secret
            "label": "Authorization: Bearer tok_from_model",
        }


class _DictObj:
    def __init__(self) -> None:
        self.password = "pw-secret"  # pragma: allowlist secret
        self.details = "api_secret=my_secret_val"


class _SlotsObj:
    __slots__ = ("val",)

    def __init__(self, val: str) -> None:
        self.val = val

    def __str__(self) -> str:
        return self.val


class _BrokenStrSlotsObj:
    __slots__ = ()

    def __str__(self) -> str:
        raise RuntimeError("cannot stringify")


class _BrokenMapping(Mapping[str, Any]):
    def __getitem__(self, key: str) -> Any:
        raise RuntimeError("broken mapping")

    def __iter__(self) -> Iterator[str]:
        return iter(())

    def __len__(self) -> int:
        return 1

    def get(self, key: str, default: Any = None) -> Any:
        raise RuntimeError("broken mapping get")


@contextmanager
def run_loopback_servers(cert_dir: Path) -> Generator[dict[str, Any], None, None]:
    """Run isolated loopback TLS 1.2+ HTTPS and plain HTTP transport servers."""
    cert_path, key_path = generate_loopback_tls_cert(cert_dir, "server")
    other_ca_path, _ = generate_loopback_tls_cert(cert_dir, "untrusted")
    combined_pem = cert_dir / "combined.pem"
    combined_pem.write_text(
        cert_path.read_text(encoding="utf-8") + key_path.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    https_srv = _RecordingHTTPSServer(("127.0.0.1", 0), cert_path, key_path)
    http_srv = _BaseRecordingServer(("127.0.0.1", 0))
    https_thread = threading.Thread(target=https_srv.serve_forever, daemon=True)
    http_thread = threading.Thread(target=http_srv.serve_forever, daemon=True)
    https_thread.start()
    http_thread.start()
    try:
        yield {
            "https_url": f"https://127.0.0.1:{https_srv.server_address[1]}/",
            "http_url": f"http://127.0.0.1:{http_srv.server_address[1]}/",
            "ca_path": cert_path,
            "key_path": key_path,
            "combined_pem": combined_pem,
            "untrusted_ca": other_ca_path,
            "https_server": https_srv,
            "http_server": http_srv,
        }
    finally:
        https_srv.shutdown_event.set()
        http_srv.shutdown_event.set()
        https_srv.shutdown()
        http_srv.shutdown()
        https_srv.server_close()
        http_srv.server_close()
        https_thread.join(timeout=5)
        http_thread.join(timeout=5)


@contextmanager
def run_builders_tls_server(cert_dir: Path) -> Generator[dict[str, Any], None, None]:
    """Run an isolated loopback HTTPS TLS 1.2+ server for builders and security integration."""
    cert_path, key_path = generate_loopback_tls_cert(cert_dir, "server")
    server = _IntegrationHTTPSServer(("localhost", 0), cert_path, key_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"https://localhost:{port}/",
            "ca_path": cert_path,
            "server": server,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


@contextmanager
def run_webhook_server() -> Generator[tuple[str, _WebhookHTTPServer], None, None]:
    """Run an isolated loopback HTTP webhook receiver for sync and async POST checks."""
    server = _WebhookHTTPServer(("127.0.0.1", 0), _WEBHOOK_SECRET)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{port}/webhook", server
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
