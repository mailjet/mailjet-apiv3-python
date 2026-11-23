"""Strict TDD regression suite for PR #179 comprehensive code review findings (#1-#14)."""

from __future__ import annotations

import ast
import asyncio
import builtins
import hashlib
import hmac
import importlib.util
import io
import json
import os
from pathlib import Path
import time
import types
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest
import responses

from mailjet_rest.builders import ChunkedStreamer
from mailjet_rest.client import AsyncClient, Client, _httpx2
from mailjet_rest.config import Config
from mailjet_rest.errors import (
    MailjetApiError,
    MailjetNetworkError,
    TimeoutError as MailjetTimeoutError,
    raise_mapped_http_error,
)
from mailjet_rest.testing import MockMailjetClient, MockResponse
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.retry import reset_stream_pointers
from mailjet_rest.webhooks import verify_webhook_signature


# ==========================================
# Cycle 1 — Issue #1: Case-Insensitive Content-Type JSON Detection
# ==========================================


@pytest.mark.parametrize(
    ("header_name", "header_value", "payload"),
    [
        ("content-type", "application/json; charset=utf-8", {"Name": "Lowercase Header"}),
        ("CONTENT-TYPE", "Application/JSON", {"Name": "Uppercase Mixed Value"}),
        ("Content-Type", "application/problem+json; charset=utf-8", [{"Name": "List PlusJson"}]),
    ],
)
def test_sync_client_case_insensitive_json_content_type_serializes_json_body(
    header_name: str,
    header_value: str,
    payload: Any,
) -> None:
    """PR #179 #1: Sync Client must serialize Mapping/list bodies as JSON for any Content-Type casing/+json."""
    captured_bodies: list[bytes | str | None] = []

    with responses.RequestsMock() as rsps:

        def _callback(request: Any) -> tuple[int, dict[str, str], str]:
            captured_bodies.append(request.body)
            return 200, {"Content-Type": "application/json"}, '{"Count": 1, "Data": []}'

        rsps.add_callback(
            responses.POST,
            "https://api.mailjet.com/v3/REST/contact",
            callback=_callback,
        )
        with Client(auth=("pub", "priv")) as client:
            resp = client.contact.create(data=payload, headers={header_name: header_value})
            assert resp.status_code == 200

    assert len(captured_bodies) == 1
    raw_body = captured_bodies[0]
    assert raw_body is not None
    parsed = json.loads(raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body)
    assert parsed == payload


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
@pytest.mark.parametrize(
    ("header_name", "header_value", "payload"),
    [
        ("content-type", "application/json; charset=utf-8", {"Name": "Async Lowercase"}),
        ("CONTENT-TYPE", "Application/JSON", {"Name": "Async Mixed"}),
        ("Content-Type", "application/merge-patch+json", {"Name": "Async PlusJson"}),
    ],
)
def test_async_client_case_insensitive_json_content_type_serializes_json_body(
    header_name: str,
    header_value: str,
    payload: Any,
) -> None:
    """PR #179 #1: AsyncClient must serialize Mapping/list bodies as JSON for any Content-Type casing/+json."""

    async def _run() -> None:
        captured_bodies: list[bytes] = []

        def _handler(request: Any) -> Any:
            captured_bodies.append(request.content)
            return _httpx2.Response(200, json={"Count": 1, "Data": []}, request=request)

        transport = _httpx2.MockTransport(_handler)
        async with AsyncClient(auth=("pub", "priv"), transport=transport) as aclient:
            resp = await aclient.contact.create(data=payload, headers={header_name: header_value})
            assert resp.status_code == 200

        assert len(captured_bodies) == 1
        assert json.loads(captured_bodies[0].decode("utf-8")) == payload

    asyncio.run(_run())


# ==========================================
# Cycle 2 — Issue #2: Fail-Closed Webhook Secret & Signed Timestamp
# ==========================================


@pytest.mark.parametrize("bad_secret", ["", "   ", "\t\n"])
def test_webhook_rejects_empty_or_whitespace_secret(bad_secret: str) -> None:
    """PR #179 #2: Empty or whitespace webhook secrets must fail closed with ValueError (CWE-321)."""
    payload = b'{"event":"sent"}'
    forged_digest = hmac.new(bad_secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()
    with pytest.raises(ValueError, match="webhook_secret must be a non-empty string"):
        verify_webhook_signature(payload, forged_digest, bad_secret)


def test_webhook_signed_timestamp_binds_timestamp_to_mac() -> None:
    """PR #179 #2: signed_timestamp=True authenticates f'{timestamp_unix}.' + payload_bytes."""
    secret = "whsec_cycle2_secret"  # pragma: allowlist secret
    payload = b'{"event":"open","MessageID":7}'
    now_ts = int(time.time())
    signed_msg = f"{now_ts}.".encode("ascii") + payload
    digest = hmac.new(secret.encode("utf-8"), signed_msg, hashlib.sha256).hexdigest()

    assert (
        verify_webhook_signature(
            payload,
            digest,
            secret,
            timestamp_unix=now_ts,
            signed_timestamp=True,
        )
        is True
    )
    # Tampering with timestamp_unix within max_age_seconds must invalidate the MAC
    assert (
        verify_webhook_signature(
            payload,
            digest,
            secret,
            timestamp_unix=now_ts - 1,
            signed_timestamp=True,
        )
        is False
    )
    with pytest.raises(ValueError, match="timestamp_unix is required"):
        verify_webhook_signature(payload, digest, secret, signed_timestamp=True)


# ==========================================
# Cycle 3 — Issue #3: AsyncClient Proxy Resolution & trust_env Isolation
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
@pytest.mark.parametrize(
    "proxies",
    [
        {"https://": "https://proxy.example.com:8443"},
        {"HTTPS": "https://proxy.example.com:8443"},
        {"all": "https://proxy.example.com:8443"},
        {"all://": "https://proxy.example.com:8443"},
    ],
)
def test_async_client_proxy_key_variants_forwarded_to_transport(proxies: dict[str, str]) -> None:
    """PR #179 #3: Standard httpx mount keys ('https://', 'all', 'HTTPS') must not silently bypass proxy."""

    async def _run() -> None:
        mock_tp = _httpx2.MockTransport(
            lambda req: _httpx2.Response(200, json={"Count": 0, "Data": []}, request=req),
        )
        async with AsyncClient(auth=("pub", "priv"), transport=mock_tp) as aclient:
            with patch.object(_httpx2, "AsyncHTTPTransport", return_value=mock_tp) as mock_http_tp:
                resp = await aclient._execute_request(
                    "GET",
                    "https://api.mailjet.com/v3/REST/contact",
                    {},
                    None,
                    None,
                    5,
                    proxies=proxies,
                )
            assert resp.status_code == 200
            assert mock_http_tp.call_args.kwargs["proxy"] == "https://proxy.example.com:8443"

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_unrecognized_nonempty_proxy_mapping_fails_closed() -> None:
    """PR #179 #3: Non-empty proxy mappings without supported scheme keys must fail closed (no silent bypass)."""

    async def _run() -> None:
        mock_tp = _httpx2.MockTransport(
            lambda req: _httpx2.Response(200, json={"Count": 0, "Data": []}, request=req),
        )
        async with AsyncClient(auth=("pub", "priv"), transport=mock_tp) as aclient:
            with pytest.raises(ValueError, match="Unsupported proxy mapping keys"):
                await aclient._execute_request(
                    "GET",
                    "https://api.mailjet.com/v3/REST/contact",
                    {},
                    None,
                    None,
                    5,
                    proxies={"ftp": "https://proxy.example.com:8443"},
                )

    asyncio.run(_run())


def test_config_and_clients_isolate_trust_env_by_default(monkeypatch: pytest.MonkeyPatch, tmp_path: Any) -> None:
    """PR #179 #3: Config.trust_env defaults to False, rejecting ambient HTTP_PROXY and .netrc unless opted in."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    netrc_file = tmp_path / ".netrc"
    netrc_file.write_text("machine api.mailjet.com login netrc_user password netrc_secret\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc_file))

    default_cfg = Config()
    assert default_cfg.trust_env is False
    with pytest.raises(TypeError, match="trust_env must be a bool"):
        Config(trust_env="yes")  # type: ignore[arg-type]

    with Client(auth="bearer_tok_123") as sync_client:
        assert sync_client.session.trust_env is False
    with Client(auth="bearer_tok_123", trust_env=True) as opted_sync:
        assert opted_sync.session.trust_env is True

    if _httpx2 is not None:

        async def _check_async_trust_env() -> None:
            async with AsyncClient(auth="bearer_tok_123") as async_client:
                assert async_client.session.trust_env is False
                seen_trust_env: list[bool] = []
                real_async_client = _httpx2.AsyncClient

                def _spy_async_client(*args: Any, **kwargs: Any) -> Any:
                    seen_trust_env.append(bool(kwargs.get("trust_env", True)))
                    kwargs["transport"] = _httpx2.MockTransport(
                        lambda req: _httpx2.Response(200, json={"Count": 0, "Data": []}, request=req),
                    )
                    return real_async_client(*args, **kwargs)

                with patch.object(_httpx2, "AsyncClient", side_effect=_spy_async_client):
                    resp = await async_client._execute_request(
                        "GET",
                        "https://api.mailjet.com/v3/REST/contact",
                        {},
                        None,
                        None,
                        5,
                        proxies={"https://": "https://proxy.example.com:8443"},
                    )
                assert resp.status_code == 200
                assert seen_trust_env == [False]

            async with AsyncClient(auth="bearer_tok_123", trust_env=True) as opted_async:
                assert opted_async.session.trust_env is True

        asyncio.run(_check_async_trust_env())


# ==========================================
# Cycle 4 — Issue #7: Scoped Idempotency Keys & Stream Retry Integrity
# ==========================================


def test_idempotency_key_scoped_by_method_url_and_sandbox_mode() -> None:
    """PR #179 #7: Idempotency-Key must differ across method, target URL, and SandboxMode."""
    fp_sandbox_true = SecurityGuard.generate_payload_fingerprint(
        {"Messages": [{"Subject": "Hi"}], "SandboxMode": True, "CustomID": "a", "EventPayload": "x"},
    )
    fp_sandbox_false = SecurityGuard.generate_payload_fingerprint(
        {"Messages": [{"Subject": "Hi"}], "SandboxMode": False, "CustomID": "b", "EventPayload": "y"},
    )
    assert fp_sandbox_true != fp_sandbox_false

    sync_keys: list[str] = []
    with responses.RequestsMock() as rsps:

        def _cb(request: Any) -> tuple[int, dict[str, str], str]:
            sync_keys.append(request.headers["Idempotency-Key"])
            return 200, {"Content-Type": "application/json"}, '{"Count": 1, "Data": []}'

        for method in (responses.PUT, responses.POST):
            rsps.add_callback(method, "https://api.mailjet.com/v3/REST/contact/1", callback=_cb)
        rsps.add_callback(responses.PUT, "https://api.mailjet.com/v3/REST/contact/2", callback=_cb)

        with Client(auth=("pub", "priv")) as sync_client:
            sync_client.contact.update(id=1, data={"IsExcludedFromCampaigns": True})
            sync_client.contact.update(id=2, data={"IsExcludedFromCampaigns": True})
            sync_client.contact.create(id=1, data={"IsExcludedFromCampaigns": True})

    assert len(sync_keys) == 3
    assert len(set(sync_keys)) == 3

    if _httpx2 is not None:

        async def _check_async() -> None:
            async_keys: list[str] = []

            def _handler(request: Any) -> Any:
                async_keys.append(request.headers["Idempotency-Key"])
                return _httpx2.Response(200, json={"Count": 1, "Data": []}, request=request)

            transport = _httpx2.MockTransport(_handler)
            async with AsyncClient(auth=("pub", "priv"), transport=transport) as aclient:
                await aclient.contact.update(id=1, data={"IsExcludedFromCampaigns": True})
                await aclient.contact.update(id=2, data={"IsExcludedFromCampaigns": True})
                await aclient.contact.create(id=1, data={"IsExcludedFromCampaigns": True})

            assert len(async_keys) == 3
            assert len(set(async_keys)) == 3

        asyncio.run(_check_async())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_nonseekable_stream_retries_preserve_payload_and_use_to_thread(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """PR #179 #7: Non-seekable streams read once via asyncio.to_thread must retain payload bytes on retry."""

    class _OneShotStream:
        def __init__(self, payload: bytes) -> None:
            self._payload = payload
            self._consumed = False
            self.read_calls = 0

        def seekable(self) -> bool:
            return False

        def read(self) -> bytes:
            self.read_calls += 1
            if self._consumed:
                return b""
            self._consumed = True
            return self._payload

    async def _run() -> None:
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        stream = _OneShotStream(b"streamed-body-bytes")
        sent_bodies: list[bytes] = []
        attempt = 0

        def _handler(request: Any) -> Any:
            nonlocal attempt
            attempt += 1
            sent_bodies.append(request.content)
            if attempt == 1:
                return _httpx2.Response(503, text="retry me", request=request)
            return _httpx2.Response(200, json={"OK": True}, request=request)

        transport = _httpx2.MockTransport(_handler)
        to_thread_calls = 0
        real_to_thread = asyncio.to_thread

        async def _spy_to_thread(func: Any, /, *args: Any, **kwargs: Any) -> Any:
            nonlocal to_thread_calls
            to_thread_calls += 1
            return await real_to_thread(func, *args, **kwargs)

        monkeypatch.setattr(asyncio, "to_thread", _spy_to_thread)

        async with AsyncClient(auth=("pub", "priv"), transport=transport, max_retries=1) as aclient:
            resp = await aclient.api_call(
                "POST",
                "https://api.mailjet.com/v3/DATA/batchjob/csverror/text:csv",
                data=stream,  # type: ignore[arg-type]
                headers={"Content-Type": "text/csv"},
            )
            assert resp.status_code == 200

        assert sent_bodies == [b"streamed-body-bytes", b"streamed-body-bytes"]
        assert stream.read_calls == 1
        assert to_thread_calls == 1

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_stream_retry_preserves_nonzero_initial_seek_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #7: Retry stream rewind must restore the caller's initial offset instead of forcing seek(0)."""
    buf = io.BytesIO(b"SKIP_HEADER___REAL_BODY")
    buf.seek(14)

    async def _run() -> None:
        monkeypatch.setattr(asyncio, "sleep", AsyncMock())
        uploads: list[bytes] = []
        attempt = 0

        async def _handler(**kwargs: Any) -> Any:
            nonlocal attempt
            attempt += 1
            part = kwargs["files"]["attachment"]
            uploads.append(part[1].read())
            if attempt == 1:
                raise _httpx2.ConnectError("transient disconnect")
            return _httpx2.Response(200, json={"OK": True}, request=_httpx2.Request("POST", kwargs["url"]))

        async with AsyncClient(auth=("pub", "priv"), max_retries=1) as aclient:
            monkeypatch.setattr(aclient.session, "request", _handler)
            resp = await aclient.contact.create(
                data={"Field": "val"},
                files={"attachment": ("slice.bin", buf, "application/octet-stream")},
            )
            assert resp.status_code == 200

        assert uploads == [b"REAL_BODY", b"REAL_BODY"]

    asyncio.run(_run())
    buf2 = io.BytesIO(b"PREFIX___TAIL")
    buf2.seek(9)
    reset_stream_pointers(buf2, None, {id(buf2): 9})
    assert buf2.tell() == 9


# ==========================================
# Cycle 5 — Issues #9a-c: Base URL Query/Fragment, Required Patch ID & Bounded response_body
# ==========================================


@pytest.mark.parametrize(
    "bad_api_url",
    [
        "https://api.mailjet.com#frag",
        "https://api.mailjet.com/#",
        "https://api.mailjet.com?a=1",
        "https://api.mailjet.com/?",
    ],
)
def test_config_api_url_rejects_query_and_fragment(bad_api_url: str) -> None:
    """PR #179 #9a: Base Config.api_url must reject query strings and fragments (including trailing bare '?' / '#')."""
    with pytest.raises(ValueError, match="fragments"):
        Config(api_url=bad_api_url)


def test_validate_target_url_rejects_fragment_allows_query() -> None:
    """PR #179 #9a: Target URLs must forbid '#' fragments while permitting '?' query parameters."""
    SecurityGuard.validate_target_url(
        "https://api.mailjet.com/v3/REST/contact?Limit=1",
        base_api_url="https://api.mailjet.com/",
    )
    with pytest.raises(ValueError, match="fragments"):
        SecurityGuard.validate_target_url(
            "https://api.mailjet.com/v3/REST/contact#frag",
            base_api_url="https://api.mailjet.com/",
        )


@pytest.mark.parametrize("bad_id", [None, "", "   ", True])
def test_endpoint_and_async_endpoint_patch_reject_invalid_id(bad_id: Any) -> None:
    """PR #179 #9b: Endpoint.patch and AsyncEndpoint.patch must reject missing, blank, or bool resource IDs."""
    with Client(auth=("pub", "priv")) as sync_client:
        with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
            sync_client.v1_templates.patch(id=bad_id, data={"Name": "Bad"})

    if _httpx2 is not None:

        async def _check() -> None:
            async with AsyncClient(auth=("pub", "priv")) as aclient:
                with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
                    await aclient.v1_templates.patch(id=bad_id, data={"Name": "Bad"})

        asyncio.run(_check())


def test_raise_mapped_http_error_bounds_response_body() -> None:
    """PR #179 #9c: MailjetApiError.response_body must be bounded by MAX_ERROR_BODY_CHARS to prevent RAM bloat."""
    from mailjet_rest import errors as errors_mod

    huge_body = "X" * 50_000
    fake_resp = types.SimpleNamespace(
        status_code=502,
        text=huge_body,
        json=lambda: (_ for _ in ()).throw(ValueError("not json")),
    )
    with pytest.raises(MailjetApiError) as exc_info:
        raise_mapped_http_error(fake_resp, RuntimeError("upstream 502"))

    max_body = getattr(errors_mod, "MAX_ERROR_BODY_CHARS", 16_384)
    assert max_body == 16_384
    assert exc_info.value.response_body == f"{huge_body[:max_body]}...[truncated]"


# ==========================================
# Cycle 6 — Issues #12 & #14a-c: Async MockClient, Builtin TimeoutError, dry_run JSON, CancelledError & AST Stubs
# ==========================================


def test_mock_client_async_await_stream_ping_and_id_validation() -> None:
    """PR #179 #12a: MockMailjetClient supports await endpoints, sync/async stream(), ping(), and ID checks."""
    with MockMailjetClient(default_status=201) as sync_mock:
        sync_ping = sync_mock.ping()
        assert bool(sync_ping) is True
        assert sync_ping == True  # noqa: E712
        sync_resp = sync_mock.send_v31.create(data={"Messages": [{"Subject": "Sync"}]})
        assert isinstance(sync_resp, MockResponse)
        assert list(sync_mock.contact.stream()) == []

    async def _run_async() -> None:
        async with MockMailjetClient(default_status=200) as async_mock:
            assert (await async_mock.ping()) is True
            resp = await async_mock.send_v31.create(data={"Messages": [{"Subject": "Async"}]})
            assert resp.status_code == 200
            assert resp.json()["Status"] == "success"
            streamed = [item async for item in async_mock.contact.stream()]
            assert streamed == []

        async with MockMailjetClient(default_status=503) as unhealthy_mock:
            assert (await unhealthy_mock.ping()) is False

    asyncio.run(_run_async())

    with MockMailjetClient() as val_mock:
        for bad_id in (None, "", "   ", True):
            with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
                val_mock.contact.patch(id=bad_id, data={"Name": "x"})  # type: ignore[arg-type]
            with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
                val_mock.contact.delete(id=bad_id)  # type: ignore[arg-type]


def test_timeout_error_inherits_from_builtin_timeout_error() -> None:
    """PR #179 #12b: mailjet_rest.errors.TimeoutError must satisfy builtins.TimeoutError handlers (PEP 3151)."""
    assert issubclass(MailjetTimeoutError, builtins.TimeoutError)
    assert issubclass(MailjetTimeoutError, MailjetNetworkError)

    def _raise_timeout() -> None:
        raise MailjetTimeoutError("request timed out")

    with pytest.raises(builtins.TimeoutError, match="request timed out"):
        _raise_timeout()


def test_dry_run_sync_and_async_return_valid_json_body() -> None:
    """PR #179 #12c: dry_run=True mutations must return valid parseable JSON payloads without raising JSONDecodeError."""
    expected = {"DryRun": True, "Count": 0, "Total": 0, "Data": [], "Messages": []}
    with Client(auth=("pub", "priv"), dry_run=True) as sync_client:
        sync_resp = sync_client.contact.create(data={"Email": "dryrun@example.com"})
        assert sync_resp.status_code == 200
        assert sync_resp.json() == expected

    if _httpx2 is not None:

        async def _check_async() -> None:
            async with AsyncClient(auth=("pub", "priv"), dry_run=True) as aclient:
                async_resp = await aclient.contact.create(data={"Email": "dryrun@example.com"})
                assert async_resp.status_code == 200
                assert async_resp.json() == expected

        asyncio.run(_check_async())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_cancelled_error_propagates_and_session_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #14b: asyncio.CancelledError during transport or retry sleep must propagate and leave client reusable."""

    async def _run() -> None:
        call_idx = 0

        async def _cancel_inflight(**kwargs: Any) -> Any:
            nonlocal call_idx
            call_idx += 1
            if call_idx == 1:
                raise asyncio.CancelledError
            return _httpx2.Response(
                200,
                json={"Recovered": True},
                request=_httpx2.Request("GET", kwargs["url"]),
            )

        async with AsyncClient(auth=("pub", "priv"), max_retries=3) as aclient:
            monkeypatch.setattr(aclient.session, "request", _cancel_inflight)
            with pytest.raises(asyncio.CancelledError):
                await aclient.contact.get()
            assert call_idx == 1  # Never retried after cancellation

            resp = await aclient.contact.get()
            assert resp.status_code == 200
            assert resp.json() == {"Recovered": True}

        # CancelledError during retry backoff sleep also propagates immediately
        attempt = 0

        async def _cancel_during_sleep_req(**kwargs: Any) -> Any:
            nonlocal attempt
            attempt += 1
            if attempt == 1:
                return _httpx2.Response(503, text="retry", request=_httpx2.Request("GET", kwargs["url"]))
            return _httpx2.Response(200, json={"OK": True}, request=_httpx2.Request("GET", kwargs["url"]))

        sleep_mock = AsyncMock(side_effect=asyncio.CancelledError)
        monkeypatch.setattr(asyncio, "sleep", sleep_mock)

        async with AsyncClient(auth=("pub", "priv"), max_retries=2) as retry_client:
            monkeypatch.setattr(retry_client.session, "request", _cancel_during_sleep_req)
            with pytest.raises(asyncio.CancelledError):
                await retry_client.contact.get()
            assert attempt == 1
            assert sleep_mock.await_count == 1

            resp2 = await retry_client.contact.get()
            assert resp2.status_code == 200

    asyncio.run(_run())


def test_check_stubs_extracts_classvars_all_and_overloads_from_ast(tmp_path: Path) -> None:
    """PR #179 #12d: check_stubs.py must extract BaseClient ClassVars, __all__, reserved_attrs, and @overload from AST."""
    script_path = Path(__file__).resolve().parents[2] / "scripts" / "check_stubs.py"
    spec = importlib.util.spec_from_file_location("check_stubs_under_test", script_path)
    assert spec is not None and spec.loader is not None
    check_stubs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_stubs)

    pkg_dir = Path(check_stubs._default_package_dir()).resolve()
    client_stub = (pkg_dir / "client.pyi").read_text(encoding="utf-8")
    for class_var in ("_TRANSIENT_STATUS_CODES", "_MAX_RETRY_DELAY", "_RETRY_ALLOWED_METHODS"):
        assert f"{class_var}: ClassVar[" in client_stub

    # Dynamic AST test on an isolated temporary package copy
    pkg_copy = tmp_path / "mailjet_rest"
    pkg_copy.mkdir()
    for fname in ("client.py", "endpoint.py", "routes.py"):
        (pkg_copy / fname).write_text((pkg_dir / fname).read_text(encoding="utf-8"), encoding="utf-8")

    # Inject an extra ClassVar + @overload method + updated __all__ export into copied client.py
    copied_client = (pkg_copy / "client.py").read_text(encoding="utf-8")
    copied_client = copied_client.replace(
        '"parse_response",\n]',
        '"parse_response",\n    "_ExtraStubExport",\n]',
    )
    copied_client = copied_client.replace(
        "_RETRY_STRATEGY: ClassVar[JitterRetry] = DEFAULT_RETRY_STRATEGY",
        "_RETRY_STRATEGY: ClassVar[JitterRetry] = DEFAULT_RETRY_STRATEGY\n    _AST_PROBE_VAR: ClassVar[int] = 42",
    )
    copied_client = copied_client.replace(
        "    def ping(self, timeout: TimeoutType = None) -> bool:",
        "    @overload\n"
        "    def overloaded_probe(self, x: int) -> int: ...\n"
        "    @overload\n"
        "    def overloaded_probe(self, x: str) -> str: ...\n"
        "    def overloaded_probe(self, x: int | str) -> int | str:\n"
        "        return x\n\n"
        "    def ping(self, timeout: TimeoutType = None) -> bool:",
    )
    (pkg_copy / "client.py").write_text(copied_client, encoding="utf-8")

    generated = check_stubs.render_client_stub(pkg_copy)
    assert "_AST_PROBE_VAR: ClassVar[int]" in generated
    assert '"_ExtraStubExport",' in generated
    assert "@overload\n    def overloaded_probe(self, x: int) -> int: ..." in generated
    assert "@overload\n    def overloaded_probe(self, x: str) -> str: ..." in generated
    assert "def overloaded_probe(self, x: int | str)" not in generated


def test_chunked_streamer_encode_file_closes_fd_on_fdopen_error_and_lexically_pairs_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeQL #87 (py/file-not-closed): encode_file must close fd if fdopen fails and pair open/close lexically."""
    sample_file = tmp_path / "attachment.txt"
    sample_file.write_bytes(b"hello-mailjet")

    real_open = os.open
    real_close = os.close
    opened_fds: list[int] = []
    closed_fds: list[int] = []

    def _spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        opened_fds.append(fd)
        return fd

    def _spy_close(fd: int) -> None:
        closed_fds.append(fd)
        real_close(fd)

    def _fail_fdopen(*_args: Any, **_kwargs: Any) -> Any:
        msg = "simulated fdopen failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "open", _spy_open)
    monkeypatch.setattr(os, "close", _spy_close)
    monkeypatch.setattr(os, "fdopen", _fail_fdopen)

    with pytest.raises(OSError, match="simulated fdopen failure"):
        ChunkedStreamer.encode_file(sample_file, safe_base_dir=tmp_path)

    assert len(opened_fds) == 1
    assert closed_fds == opened_fds, f"Leaked fd(s) {set(opened_fds) - set(closed_fds)} when os.fdopen raised"

    # AST lexical pairing witness so CodeQL py/file-not-closed can prove fd closure within encode_file
    builders_path = Path(__file__).resolve().parents[2] / "mailjet_rest" / "builders.py"
    tree = ast.parse(builders_path.read_text(encoding="utf-8"), filename=str(builders_path))
    streamer_cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ChunkedStreamer")
    encode_fn = next(
        node for node in streamer_cls.body if isinstance(node, ast.FunctionDef) and node.name == "encode_file"
    )
    os_calls = {
        node.func.attr
        for node in ast.walk(encode_fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    }
    assert {"open", "fdopen", "close"} <= os_calls
    has_try_finally = any(isinstance(node, ast.Try) and bool(node.finalbody) for node in ast.walk(encode_fn))
    assert has_try_finally, "ChunkedStreamer.encode_file must pair os.open with try/finally os.close"
