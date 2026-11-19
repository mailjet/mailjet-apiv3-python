"""Offline real-socket TLS 1.2+ integration tests exercising Client and AsyncClient end-to-end."""

from __future__ import annotations

import asyncio
import http.server
import io
import json
import shutil
import ssl
import subprocess
import threading
import warnings
from collections.abc import Generator
from pathlib import Path
from typing import Any

import pytest

from mailjet_rest import (
    AsyncClient,
    Client,
    Config,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    ValidationError,
)
from mailjet_rest.builders import MessageBuilder, SendPayloadBuilder
from mailjet_rest.client import _httpx2


class _RecordingMailjetHandler(http.server.BaseHTTPRequestHandler):
    """Thread-safe local HTTPS Mailjet stub validating wire headers, payloads, retries, and redirects."""

    server: _RecordingHTTPSServer

    def log_message(self, format: str, *args: Any) -> None:
        """Silence stdlib HTTPServer stderr noise during pytest runs."""
        _ = (format, args)

    def _read_body(self) -> bytes:
        length = int(self.headers.get("Content-Length", "0") or "0")
        return self.rfile.read(length) if length > 0 else b""

    def _write_json(self, status: int, payload: dict[str, Any], extra_headers: dict[str, str] | None = None) -> None:
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
        self.end_headers()
        if encoded:
            self.wfile.write(encoded)

    def _record(self, method: str, body: bytes) -> None:
        self.server.recorded_requests.append(
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

        if self.headers.get("Authorization") == "Basic aW52YWxpZDppbnZhbGlk":
            self._write_json(401, {"ErrorMessage": "Invalid credentials"})
            return

        if self.path.startswith("/v3/REST/apikey"):
            if self.headers.get("Authorization") == "Bearer fail_ping":
                self._write_json(503, {"ErrorMessage": "Service down"})
            else:
                self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 1}]})
            return

        if self.path.startswith("/v3/DATA/batchjob/77/CSVError/text:csv"):
            self._write_json(200, {"Count": 0, "Total": 0, "Data": []})
            return

        if self.path.startswith("/v3/REST/contact"):
            if "Offset=0" in self.path:
                self._write_json(200, {"Count": 2, "Total": 2, "Data": [{"ID": 1}, {"ID": 2}]})
            elif "Offset=2" in self.path:
                self._write_json(200, {"Count": 2, "Total": 2, "Data": [{"ID": 3}, {"ID": 4}]})
            elif "Offset=4" in self.path:
                self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 5}]})
            else:
                self._write_json(200, {"Count": 1, "Total": 1, "Data": [{"ID": 1}]})
            return

        if self.path.startswith("/v3/REST/redirect"):
            self.send_response(302)
            self.send_header("Location", "https://evil.example/steal-auth")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return

        if self.path.startswith("/v3/REST/notfound"):
            self._write_json(404, {"ErrorMessage": "Object not found"})
            return

        if self.path.startswith("/v3/REST/servererr"):
            self._write_json(502, {"ErrorMessage": "Bad gateway upstream"})
            return

        self._write_json(200, {"Count": 0, "Total": 0, "Data": []})

    def do_POST(self) -> None:
        body = self._read_body()
        self._record("POST", body)

        if self.path.startswith("/v3.1/send"):
            if b"invalid-recipient" in body:
                self._write_json(
                    400,
                    {"Messages": [{"Errors": [{"ErrorMessage": "Invalid recipient address"}]}]},
                )
                return
            self._write_json(200, {"Messages": [{"Status": "success"}]})
            return

        if self.path.startswith("/v3/REST/flaky"):
            attempt = self.server.flaky_calls
            self.server.flaky_calls += 1
            if attempt < 2:
                self._write_json(429, {"ErrorMessage": "Rate limit"}, extra_headers={"Retry-After": "0"})
                return
            self._write_json(201, {"Count": 1, "Data": [{"ID": 99}], "echo_len": len(body)})
            return

        if self.path.startswith("/v1/data/images"):
            ctype = self.headers.get("Content-Type", "")
            self._write_json(201, {"Count": 1, "Data": [{"ID": "img-1", "content_type": ctype}]})
            return

        self._write_json(201, {"Count": 1, "Data": [{"ID": 100}]})

    def do_PUT(self) -> None:
        body = self._read_body()
        self._record("PUT", body)
        if self.path.startswith("/v3/REST/contact/42"):
            self.send_response(304)
            self.end_headers()
            return
        self._write_json(200, {"Count": 1, "Data": [{"ID": 42}]})


class _RecordingHTTPSServer(http.server.ThreadingHTTPServer):
    allow_reuse_address = True

    def __init__(self, server_address: tuple[str, int], cert_path: Path, key_path: Path) -> None:
        super().__init__(server_address, _RecordingMailjetHandler)
        self.recorded_requests: list[dict[str, Any]] = []
        self.flaky_calls = 0
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(cert_path), keyfile=str(key_path))
        self.socket = ctx.wrap_socket(self.socket, server_side=True)


def _generate_self_signed_cert(cert_dir: Path, name: str) -> tuple[Path, Path]:
    openssl = shutil.which("openssl")
    if openssl is None:
        pytest.skip("openssl binary not available for loopback TLS integration test")
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
def local_tls_server(tmp_path_factory: pytest.TempPathFactory) -> Generator[dict[str, Any], None, None]:
    """Start an isolated loopback HTTPS TLS 1.2+ server with valid and untrusted CA certs."""
    cert_dir = tmp_path_factory.mktemp("tls_loopback")
    cert_path, key_path = _generate_self_signed_cert(cert_dir, "server")
    other_ca_path, _ = _generate_self_signed_cert(cert_dir, "untrusted")

    server = _RecordingHTTPSServer(("localhost", 0), cert_path, key_path)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield {
            "url": f"https://localhost:{port}/",
            "ca_path": cert_path,
            "untrusted_ca": other_ca_path,
            "server": server,
        }
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_sync_client_real_tls_loopback_lifecycle(local_tls_server: dict[str, Any]) -> None:
    """Exercise sync Client over real TLS 1.2+ sockets: auth, headers, 304, 302 no-follow, streaming, retries, errors."""
    server: _RecordingHTTPSServer = local_tls_server["server"]
    server.recorded_requests.clear()
    server.flaky_calls = 0
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]

    with Client(auth=("pub", "priv"), config=Config(api_url=url, verify=ca_path, max_retries=0)) as client:
        assert client.ping() is True

        # Send v3.1 with builders and verify Idempotency-Key + Basic Auth on the wire
        msg = (
            MessageBuilder()
            .set_sender("pilot@example.com")
            .add_recipient("passenger@example.com")
            .set_subject("Loopback TLS")
            .set_content(text="Hello over TLS 1.2+")
            .build()
        )
        payload = SendPayloadBuilder().add_message(msg).build()
        send_resp = client.send_v31.create(data=payload)
        assert send_resp.status_code == 200
        wire_send = server.recorded_requests[-1]
        assert wire_send["path"] == "/v3.1/send"
        assert "idempotency-key" in wire_send["headers"]
        assert wire_send["headers"]["authorization"].startswith("Basic ")

        # Stream pagination across 3 real socket round-trips
        streamed = [item["ID"] for item in client.contact.stream(chunk_size=2, max_items=5)]
        assert streamed == [1, 2, 3, 4, 5]

        # _csverror uses Content-Type: text/csv on the wire
        csv_err = client.batchjob_csverror.get(id=77)
        assert csv_err.status_code == 200
        assert server.recorded_requests[-1]["headers"]["content-type"] == "text/csv"

        # 304 Not Modified succeeds without triggering unexpected_redirect warning
        with warnings.catch_warnings(record=True) as wlist:
            warnings.simplefilter("always")
            put_304 = client.contact.update(id=42, data={"Name": "Unchanged"})
        assert put_304.status_code == 304
        assert not [w for w in wlist if "redirect" in str(w.message).lower()]

        # 302 Found is NOT followed to evil.example
        redir = client.redirect.get()
        assert redir.status_code == 302
        assert redir.headers["Location"] == "https://evil.example/steal-auth"

        # Multipart file upload strips application/json and generates multipart boundary
        up = client.data_images.create(
            headers={"Content-Type": None},
            files={"file": ("logo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")},
        )
        assert up.status_code == 201
        assert "multipart/form-data" in up.json()["Data"][0]["content_type"]

        # Error mappings
        try:
            client.send_v31.create(data={"Messages": ["invalid-recipient"]})
        except ValidationError as exc:
            assert "Invalid recipient address" in str(exc)
        else:
            raise AssertionError("Expected ValidationError for invalid-recipient")

        try:
            client.notfound.get()
        except DoesNotExistError as exc:
            assert exc.status_code == 404
        else:
            raise AssertionError("Expected DoesNotExistError")

        try:
            client.servererr.get()
        except MailjetApiError as exc:
            assert exc.status_code == 502
        else:
            raise AssertionError("Expected MailjetApiError")

    # Wrong CA bundle must fail TLS verification closed
    with Client(auth=("pub", "priv"), api_url=url, verify=local_tls_server["untrusted_ca"], max_retries=0) as bad_ca:
        with pytest.raises(CriticalApiError):
            bad_ca.contact.get()

    # Invalid Basic auth -> MailjetAuthError (401)
    with Client(auth=("invalid", "invalid"), api_url=url, verify=ca_path, max_retries=0) as bad_auth:
        with pytest.raises(MailjetAuthError):
            bad_auth.contact.get()
        assert bad_auth.ping() is False


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_real_tls_loopback_retries_and_lifecycle(local_tls_server: dict[str, Any]) -> None:
    """Exercise AsyncClient over real TLS 1.2+ sockets: retries on 429, stream, Bearer ping, and untrusted CA."""
    server: _RecordingHTTPSServer = local_tls_server["server"]
    server.flaky_calls = 0
    url: str = local_tls_server["url"]
    ca_path: Path = local_tls_server["ca_path"]

    async def _run() -> None:
        async with AsyncClient(auth="valid_bearer", config=Config(api_url=url, verify=ca_path, max_retries=3)) as ac:
            assert await ac.ping() is True
            streamed = [item["ID"] async for item in ac.contact.stream(chunk_size=2, max_items=5)]
            assert streamed == [1, 2, 3, 4, 5]

            # Real socket 429 retry recovery with BytesIO rewind
            buf = io.BytesIO(b"hello-async-tls")
            flaky_resp = await ac.api_call("POST", f"{url}v3/REST/flaky", data=buf)
            assert flaky_resp.status_code == 201
            assert flaky_resp.json()["echo_len"] == len(b"hello-async-tls")

            # Per-call custom verify override isolates transport cleanly
            with pytest.raises(CriticalApiError):
                await ac.api_call("GET", f"{url}v3/REST/contact", verify=local_tls_server["untrusted_ca"])

        async with AsyncClient(auth="fail_ping", config=Config(api_url=url, verify=ca_path, max_retries=0)) as fail_ac:
            assert await fail_ac.ping() is False

    asyncio.run(_run())
