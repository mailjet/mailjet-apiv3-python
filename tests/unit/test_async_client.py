"""Unit tests for the asynchronous Mailjet API client (AsyncClient backed by httpx2)."""

from __future__ import annotations

import asyncio
import base64
import copy
import gc
import io
import logging
import socket
import ssl
import sys
import uuid
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock

import pytest
import requests

from mailjet_rest.client import AsyncClient, Client, Config, _httpx2, parse_response
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import (
    ApiError,
    ApiRateLimitError,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    TimeoutError,  # ruff: ignore[builtin-import-shadowing]
    ValidationError,
)
from mailjet_rest.utils.guardrails import SecretAuth


# ==========================================
# 1. Dependency Guard, Lazy Boot & Auth Tests
# ==========================================


def test_async_client_import_error_when_httpx2_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncClient raises ImportError when httpx2 is unavailable."""
    monkeypatch.setattr("mailjet_rest.client._httpx2", None)
    with pytest.raises(ImportError, match="AsyncClient requires 'httpx2>=2.0.0'"):
        AsyncClient(auth=("pub", "priv"))


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_auth_modes_and_header_application() -> None:
    """Verify Basic Auth (SecretAuth), Bearer auth, redaction, and outgoing Authorization headers."""

    async def _run() -> None:
        captured_headers: list[str] = []

        def transport_handler(request: Any) -> Any:
            captured_headers.append(request.headers.get("Authorization", ""))
            return _httpx2.Response(200, json={"ok": True}, request=request)

        async with AsyncClient(auth=("super_secret_pub", "super_secret_priv")) as basic_client:
            assert isinstance(basic_client.auth, SecretAuth)
            assert basic_client.auth == ("super_secret_pub", "super_secret_priv")
            assert "super_secret" not in repr(basic_client)
            assert "Mailjet AsyncClient" in str(basic_client)
            assert "Authorization" not in basic_client.session.headers

            basic_client.session = _httpx2.AsyncClient(
                auth=basic_client._build_auth_and_headers()[0],
                headers=basic_client._build_auth_and_headers()[1],
                follow_redirects=False,
                transport=_httpx2.MockTransport(transport_handler),
            )
            await basic_client.contact.get()
            expected_token = base64.b64encode(b"super_secret_pub:super_secret_priv").decode("ascii")
            assert captured_headers == [f"Basic {expected_token}"]

        async with AsyncClient(auth="bearer_token_abc") as bearer_client:
            assert bearer_client.auth == "bearer_token_abc"
            assert bearer_client.session.headers.get("Authorization") == "Bearer bearer_token_abc"

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_lazy_session_tls_keepalive_and_warn_unclosed() -> None:
    """Verify lazy session creation, TLS 1.2+ transport, keep-alive socket options, and ResourceWarning."""

    async def _run() -> None:
        cfg = Config(pool_connections=10, pool_maxsize=20)
        async with AsyncClient(auth=("pub_key", "priv_key"), config=cfg) as aclient:
            assert aclient._session is None
            _ = aclient.contact
            assert aclient._session is None

            session = aclient.session
            assert session.follow_redirects is False
            assert getattr(aclient, "_session") is session

            transport = getattr(session, "_transport", None)
            assert isinstance(transport, _httpx2.AsyncHTTPTransport)
            pool = getattr(transport, "_pool", None)
            assert pool is not None
            ssl_ctx = pool._ssl_context
            assert isinstance(ssl_ctx, ssl.SSLContext)
            assert ssl_ctx.minimum_version == ssl.TLSVersion.TLSv1_2
            assert ssl_ctx.verify_mode == ssl.CERT_REQUIRED
            assert ssl_ctx.check_hostname is True
            assert (socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1) in (pool._socket_options or ())

    asyncio.run(_run())

    with warnings.catch_warnings(record=True) as quiet_warnings:
        warnings.simplefilter("always", ResourceWarning)
        c_quiet = AsyncClient(auth=("pub_key", "priv_key"))
        _ = c_quiet.session
        del c_quiet
        gc.collect()
    assert not [w for w in quiet_warnings if issubclass(w.category, ResourceWarning)]

    with pytest.warns(ResourceWarning, match="Unclosed Mailjet AsyncClient session"):
        c_warn = AsyncClient(auth=("pub_key", "priv_key"), warn_unclosed=True)
        _ = c_warn.session
        del c_warn
        gc.collect()


# ==========================================
# 2. Lifecycle, Payloads, Idempotency & Security Guards
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_lifecycle_and_payload_execution(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify endpoint caching, dry_run, tuple timeouts, JSON vs raw content, parse_response, and teardown."""

    async def _run() -> None:
        async with AsyncClient(auth=("pub_key", "priv_key"), dry_run=True) as aclient:
            first_contact = aclient.contact
            second_contact = aclient.contact
            assert isinstance(first_contact, AsyncEndpoint)
            assert first_contact is second_contact
            assert not hasattr(aclient, "__dict__")
            assert not hasattr(first_contact, "__dict__")

            resp = await aclient.contact.create(data={"Name": "AsyncUser"})
            assert resp.status_code == 200
            resp.raise_for_status()

        client = AsyncClient(auth=("pub_key", "priv_key"))
        captured_kwargs: dict[str, Any] = {}

        async def mock_async_request(**kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            req = _httpx2.Request(kwargs.get("method", "GET"), kwargs.get("url", "https://api.mailjet.com"))
            return _httpx2.Response(200, json={"Count": 1, "Total": 1, "Data": [{"ID": 42}]}, request=req)

        monkeypatch.setattr(client.session, "request", mock_async_request)

        res_post = await client.api_call(
            "POST",
            "https://api.mailjet.com/v3/REST/contact",
            data={"Email": "a@b.com"},
            headers={"Content-Type": "application/json"},
            timeout=(2.0, 5.0),
        )
        assert res_post.status_code == 200
        assert captured_kwargs.get("json") == {"Email": "a@b.com"}
        assert isinstance(captured_kwargs["timeout"], _httpx2.Timeout)
        with pytest.warns(DeprecationWarning, match="parse_response"):
            assert parse_response(res_post)["Count"] == 1

        captured_kwargs.clear()

        async def mock_async_202(**kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            req = _httpx2.Request(kwargs.get("method", "POST"), kwargs.get("url", "https://api.mailjet.com"))
            return _httpx2.Response(202, text="Accepted", request=req)

        monkeypatch.setattr(client.session, "request", mock_async_202)
        res_raw = await client.api_call(
            "POST",
            "https://api.mailjet.com/v3/DATA/contactslist/1/CSVData/text:plain",
            data="email\na@b.com",
            headers={"Content-Type": "text/plain"},
        )
        assert res_raw.status_code == 202
        assert captured_kwargs.get("content") == "email\na@b.com"

        await client.close()
        client.session = None
        await client.aclose()

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_idempotency_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fingerprint, uuid4, and off auto_idempotency_mode parity on AsyncClient."""

    async def _run() -> None:
        async def ok_request(**kwargs: Any) -> Any:
            captured_headers.append(dict(kwargs.get("headers", {})))
            req = _httpx2.Request("POST", "https://api.mailjet.com/v3/REST/contact")
            return _httpx2.Response(200, json={"Data": []}, request=req)

        captured_headers: list[dict[str, Any]] = []
        async with AsyncClient(auth=("k", "s"), config=Config(auto_idempotency_mode="fingerprint")) as c_fp:
            monkeypatch.setattr(c_fp.session, "request", ok_request)
            await c_fp.contact.create(data={"Email": "idemp@example.com"})
        assert "Idempotency-Key" in captured_headers[-1]

        captured_headers.clear()
        async with AsyncClient(auth=("k", "s"), config=Config(auto_idempotency_mode="uuid4")) as c_uuid:
            monkeypatch.setattr(c_uuid.session, "request", ok_request)
            await c_uuid.contact.create(data={"Email": "idemp@example.com"})
        parsed = uuid.UUID(captured_headers[-1]["Idempotency-Key"])
        assert parsed.version == 4

        captured_headers.clear()
        async with AsyncClient(auth=("k", "s"), config=Config(auto_idempotency_mode="off")) as c_off:
            monkeypatch.setattr(c_off.session, "request", ok_request)
            await c_off.contact.create(data={"Email": "idemp@example.com"})
        assert "Idempotency-Key" not in captured_headers[-1]

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_security_guards_ca_isolation_and_redirects(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify SSRF re-validation, redirect rejection, 3xx audit warning, and per-call CA override isolation."""
    ca_file = tmp_path / "custom-ca.pem"
    ca_file.write_text("dummy-ca", encoding="utf-8")

    async def _run() -> None:
        async with AsyncClient(auth=("k", "s")) as aclient:
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact", allow_redirects=True)
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact", follow_redirects=True)

            # 3xx redirect audit event + warning
            req = _httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")
            resp_302 = _httpx2.Response(302, headers={"Location": "https://evil.example.com"}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=resp_302))

            audit_events: list[tuple[str, tuple[Any, ...]]] = []

            def audit_hook(event: str, args: tuple[Any, ...]) -> None:
                if event == "mailjet.security.unexpected_redirect":
                    audit_events.append((event, args))

            sys.addaudithook(audit_hook)
            with caplog.at_level(logging.WARNING):
                res = await aclient.contact.get()
            assert res.status_code == 302
            assert any(e[0] == "mailjet.security.unexpected_redirect" and e[1][1] == 302 for e in audit_events)
            assert "redirects are disabled" in caplog.text

            # Per-call CA bundle uses isolated ephemeral transport without warning
            ephemeral_calls: list[Any] = []
            default_pool = getattr(getattr(aclient.session, "_transport", None), "_pool", None)
            default_ssl_ctx = getattr(default_pool, "_ssl_context", None)

            async def fake_ephemeral(
                _self: AsyncClient,
                httpx2_mod: Any,
                req_verify: bool | str,
                proxies: Any,
                cert: Any,
                req_kwargs: dict[str, Any],
            ) -> Any:
                ephemeral_calls.append((req_verify, proxies, cert, req_kwargs["url"]))
                return _httpx2.Response(200, json={"Data": []}, request=req)

            monkeypatch.setattr(AsyncClient, "_request_isolated", fake_ephemeral)
            with warnings.catch_warnings(record=True) as dep_warnings:
                warnings.simplefilter("always", DeprecationWarning)
                ca_res = await aclient.api_call(
                    "GET",
                    "https://api.mailjet.com/v3/REST/contact",
                    verify=str(ca_file),
                )
            assert ca_res.status_code == 200
            assert not dep_warnings
            assert ephemeral_calls[0][0] == str(ca_file)
            current_pool = getattr(getattr(aclient.session, "_transport", None), "_pool", None)
            assert getattr(current_pool, "_ssl_context", None) is default_ssl_ctx

            # Post-init config.api_url SSRF mutation is blocked at request time
            aclient.config.api_url = "https://evil.example.com/"
            with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact")

            aclient.config.api_url = "ftp://api.mailjet.com/"
            with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact")

    asyncio.run(_run())


# ==========================================
# 3. Exception Mapping Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_error_handling_branches(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncClient maps TimeoutException, ConnectError/NetworkError, and HTTPStatusError accurately."""

    async def _run() -> None:
        async with AsyncClient(auth=("pub_key", "priv_key"), max_retries=0) as aclient:
            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(side_effect=_httpx2.TimeoutException("Async read timed out")),
            )
            with pytest.raises(TimeoutError, match="Request to Mailjet API timed out"):
                await aclient.contact.get()

            for conn_exc in (
                _httpx2.ConnectError("Async connection refused"),
                _httpx2.NetworkError("Async network drop"),
                _httpx2.RemoteProtocolError("Async protocol reset"),
            ):
                monkeypatch.setattr(aclient.session, "request", AsyncMock(side_effect=conn_exc))
                with pytest.raises(CriticalApiError, match="Connection to Mailjet API failed"):
                    await aclient.contact.get()

            for status, exc_cls in (
                (401, MailjetAuthError),
                (403, MailjetAuthError),
                (429, ApiRateLimitError),
                (404, DoesNotExistError),
                (400, ValidationError),
                (500, MailjetApiError),
                (503, MailjetApiError),
            ):
                req = _httpx2.Request("GET", "https://api.mailjet.com/v3/REST/contact")
                resp = _httpx2.Response(status, json={"ErrorMessage": f"err-{status}"}, request=req)
                monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=resp))
                with pytest.raises(exc_cls, match=f"err-{status}"):
                    await aclient.contact.get()

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(side_effect=_httpx2.HTTPError("Generic httpx2 failure")),
            )
            with pytest.raises(ApiError, match="An unexpected Mailjet API network error occurred"):
                await aclient.contact.get()

    asyncio.run(_run())


# ==========================================
# 5. Mailgun-Inspired Transport, Lifecycle, Retry & Concurrency Tests
# ==========================================


def test_config_max_retries_validation() -> None:
    """Verify Config.max_retries accepts integers >= 0 and rejects booleans, negatives, and non-ints."""
    assert Config().max_retries == 3
    assert Config(max_retries=0).max_retries == 0
    assert Config(max_retries=5).max_retries == 5

    bad_values: tuple[Any, ...] = (-1, True, False, "2", 1.5)
    for bad_val in bad_values:
        with pytest.raises(ValueError, match="max_retries"):
            Config(max_retries=bad_val)


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_custom_transport_and_ping(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify custom httpx2 transport injection and ping() behavior across AsyncClient and Client."""
    assert _httpx2 is not None

    async def _run() -> None:
        seen_urls: list[str] = []
        seen_auths: list[str] = []
        status_queue = [200, 401, 500]

        def handler(request: Any) -> Any:
            seen_urls.append(str(request.url))
            seen_auths.append(request.headers.get("Authorization", ""))
            if not status_queue:
                raise _httpx2.ConnectError("simulated outage")
            return _httpx2.Response(status_queue.pop(0), json={"Data": []})

        transport = _httpx2.MockTransport(handler)
        async with AsyncClient(auth=("pub_key", "priv_key"), transport=transport, max_retries=0) as aclient:
            resp = await aclient.contact.get()
            assert resp.status_code == 200
            assert seen_auths[0].startswith("Basic ")

        # Verify AsyncClient.ping() true / auth fail / server error / connect error / SSRF fail-closed
        ping_outcomes: list[Any] = [200, 401, 503, _httpx2.ConnectError("network down")]

        def ping_handler(_request: Any) -> Any:
            outcome = ping_outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return _httpx2.Response(outcome, json={"Data": []})

        async with AsyncClient(
            auth=("pub_key", "priv_key"),
            transport=_httpx2.MockTransport(ping_handler),
            max_retries=0,
        ) as ping_client:
            assert await ping_client.ping(timeout=2.0) is True
            assert await ping_client.ping() is False
            assert await ping_client.ping() is False
            assert await ping_client.ping() is False

            ping_client.config.api_url = "https://evil.example.com/"
            with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
                await ping_client.ping()

        assert "contact" in seen_urls[0]

    asyncio.run(_run())

    # Sync Client.ping()
    with Client(auth=("pub_key", "priv_key")) as sync_client:
        fake_ok = type(
            "Resp",
            (),
            {"status_code": 200, "headers": {}, "text": "{}", "raise_for_status": lambda _s=None: None},
        )()
        monkeypatch.setattr(sync_client.session, "request", lambda **_kw: fake_ok)
        assert sync_client.ping(timeout=1.0) is True

        def fail_conn(**_kw: Any) -> Any:
            raise requests.exceptions.ConnectionError("down")

        monkeypatch.setattr(sync_client.session, "request", fail_conn)
        assert sync_client.ping() is False


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_pool_self_healing_reentry_and_exception_purge() -> None:
    """Verify pool self-healing on .is_closed, context re-entry, and exception credential purge."""
    assert _httpx2 is not None

    async def _run() -> None:
        # 1. Pool self-healing when underlying httpx2 session is closed directly
        heal_client = AsyncClient(auth=("k", "s"))
        sess1 = heal_client.session
        assert not sess1.is_closed
        await sess1.aclose()
        assert sess1.is_closed

        sess2 = heal_client.session
        assert sess2 is not sess1
        assert not sess2.is_closed
        await heal_client.aclose()

        # 2. Exception purge on exit and clean context manager re-entry
        reusable = AsyncClient(auth=("k", "s"))
        inner_sess = reusable.session
        with pytest.raises(RuntimeError, match="boom"):
            async with reusable as entered:
                assert entered is reusable
                assert entered.session is inner_sess
                _raise_boom("boom", trigger=bool(inner_sess))

        assert inner_sess.is_closed
        assert inner_sess.auth is None
        assert "Authorization" not in inner_sess.headers
        assert reusable._session is None  # ruff: ignore[private-member-access]

        async with reusable as second_entry:
            rebuilt_sess = second_entry.session
            assert rebuilt_sess is not inner_sess
            assert not rebuilt_sess.is_closed

    def _raise_boom(msg: str, *, trigger: bool = True) -> None:
        if trigger:
            raise RuntimeError(msg)

    asyncio.run(_run())

    # Sync Client re-entry check
    sync_client = Client(auth=("k", "s"))
    with pytest.raises(RuntimeError, match="sync boom"):
        with sync_client as s1:
            _raise_boom("sync boom", trigger=bool(s1.session))
    assert sync_client._session is None  # ruff: ignore[private-member-access]
    with sync_client as s2:
        assert s2.session is not None


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_client_copy_deepcopy_isolation_and_dunder_rejection() -> None:
    """Verify __copy__ and __deepcopy__ isolate locks/sessions/caches without SecretAuth warnings."""
    assert _httpx2 is not None

    transport = _httpx2.MockTransport(lambda _r: _httpx2.Response(200, json={"Data": []}))
    orig = AsyncClient(
        auth=("k_secret", "s_secret"),
        config=Config(version="v3.1", max_retries=2),
        transport=transport,
    )
    _ = orig.session
    _ = orig.send

    with warnings.catch_warnings(record=True) as captured:
        warnings.simplefilter("always")
        shallow = copy.copy(orig)
        deep = copy.deepcopy(orig)
    assert not [w for w in captured if issubclass(w.category, UserWarning)]

    assert shallow is not orig
    assert deep is not orig
    assert shallow._lock is not orig._lock  # ruff: ignore[private-member-access]
    assert deep._lock is not orig._lock  # ruff: ignore[private-member-access]
    assert shallow._session is None  # ruff: ignore[private-member-access]
    assert deep._session is None  # ruff: ignore[private-member-access]
    assert shallow._endpoint_cache == {}  # ruff: ignore[private-member-access]
    assert deep._endpoint_cache == {}  # ruff: ignore[private-member-access]
    assert shallow._custom_transport is None  # ruff: ignore[private-member-access]
    assert deep._custom_transport is None  # ruff: ignore[private-member-access]
    assert shallow.config is not orig.config
    assert shallow.config == orig.config
    shallow.config.max_retries = 0
    assert orig.config.max_retries == 2
    assert deep.config is not orig.config
    assert deep.config.version == "v3.1"
    assert deep.auth is not orig.auth
    assert isinstance(deep.auth, SecretAuth)
    assert isinstance(orig.auth, SecretAuth)
    assert deep.auth.auth_header == orig.auth.auth_header

    # Sync Client deepcopy + private/dunder rejection
    sync_orig = Client(auth=("k_sync", "s_sync"))
    _ = sync_orig.session
    sync_deep = copy.deepcopy(sync_orig)
    assert sync_deep._session is None  # ruff: ignore[private-member-access]
    assert sync_deep._lock is not sync_orig._lock  # ruff: ignore[private-member-access]

    for bad_attr in ("_private_attr", "__nonexistent_dunder__"):
        with pytest.raises(AttributeError):
            _ = getattr(orig, bad_attr)

    sync_orig.close()
    asyncio.run(orig.aclose())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_retry_backoff_rewind_fast_fail_and_causes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify retries with capped Retry-After, BytesIO rewind, fast-fail errors, and PEP 3134 __cause__."""
    assert _httpx2 is not None

    async def _run() -> None:
        sleep_mock = AsyncMock()
        monkeypatch.setattr(asyncio, "sleep", sleep_mock)

        # 1. Transient 503 (capped Retry-After: 120 -> 60.0) -> 429 (invalid date -> jitter) -> 200
        req = _httpx2.Request("POST", "https://api.mailjet.com/v3/REST/contact")
        responses = [
            _httpx2.Response(503, headers={"Retry-After": "120"}, request=req),
            _httpx2.Response(429, headers={"Retry-After": "not-a-float"}, request=req),
            _httpx2.Response(200, json={"Count": 1}, request=req),
        ]
        async with AsyncClient(auth=("k", "s"), max_retries=3) as aclient:
            mock_req = AsyncMock(side_effect=responses)
            monkeypatch.setattr(aclient.session, "request", mock_req)
            resp = await aclient.contact.create(data={"Email": "retry@example.com"})
            assert resp.status_code == 200
            assert mock_req.await_count == 3
            assert sleep_mock.await_count == 2
            assert sleep_mock.await_args_list[0].args[0] == 60.0
            assert 0.0 <= sleep_mock.await_args_list[1].args[0] <= 2.0

        # 2. Multipart upload strips default application/json Content-Type & rewinds BytesIO on retry
        sleep_mock.reset_mock()
        bio = io.BytesIO(b"hello-multipart-payload")
        observed_uploads: list[tuple[dict[str, Any], bytes]] = []
        attempt_idx = 0

        async def upload_handler(**kwargs: Any) -> Any:
            nonlocal attempt_idx
            attempt_idx += 1
            file_tuple = kwargs["files"]["attachment"]
            chunk = file_tuple[1].read()
            observed_uploads.append((dict(kwargs["headers"]), chunk))
            if attempt_idx == 1:
                raise _httpx2.ConnectError("socket dropped mid-upload")
            return _httpx2.Response(200, json={"OK": True}, request=req)

        async with AsyncClient(auth=("k", "s"), max_retries=2) as upload_client:
            monkeypatch.setattr(upload_client.session, "request", upload_handler)
            res = await upload_client.contact.create(
                data={"Field": "value"},
                files={"attachment": ("note.txt", bio, "text/plain")},
            )
            assert res.status_code == 200
            assert len(observed_uploads) == 2
            assert "Content-Type" not in observed_uploads[0][0]
            assert observed_uploads[0][1] == b"hello-multipart-payload"
            assert observed_uploads[1][1] == b"hello-multipart-payload"

        # 3. Fast-fail on UnsupportedProtocol & DecodingError without sleeping/retrying
        sleep_mock.reset_mock()
        for fast_exc_cls in (_httpx2.UnsupportedProtocol, _httpx2.DecodingError):
            fast_exc = fast_exc_cls("non-retryable")
            async with AsyncClient(auth=("k", "s"), max_retries=3) as ff_client:
                mock_ff = AsyncMock(side_effect=fast_exc)
                monkeypatch.setattr(ff_client.session, "request", mock_ff)
                with pytest.raises(ApiError) as exc_info:
                    await ff_client.contact.get()
                assert mock_ff.await_count == 1
                assert sleep_mock.await_count == 0
                assert exc_info.value.__cause__ is fast_exc

        # 4. PEP 3134 __cause__ preserved when retries are exhausted
        sleep_mock.reset_mock()
        async with AsyncClient(auth=("k", "s"), max_retries=1) as cause_client:
            to_exc = _httpx2.TimeoutException("read timeout")
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(side_effect=to_exc))
            with pytest.raises(TimeoutError) as to_info:
                await cause_client.contact.get()
            assert to_info.value.__cause__ is to_exc

            conn_exc = _httpx2.ConnectError("refused")
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(side_effect=conn_exc))
            with pytest.raises(CriticalApiError) as conn_info:
                await cause_client.contact.get()
            assert conn_info.value.__cause__ is conn_exc

            resp_503 = _httpx2.Response(503, text="backend unavailable", request=req)
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(return_value=resp_503))
            with pytest.raises(MailjetApiError) as http_info:
                await cause_client.contact.get()
            assert isinstance(http_info.value.__cause__, _httpx2.HTTPStatusError)

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_concurrent_gather_requests() -> None:
    """Verify AsyncClient executes concurrent asyncio.gather requests safely via shared transport."""
    assert _httpx2 is not None

    async def _run() -> None:
        observed_paths: list[str] = []

        def handler(request: Any) -> Any:
            observed_paths.append(request.url.path)
            return _httpx2.Response(200, json={"Path": request.url.path})

        async with AsyncClient(
            auth=("k", "s"),
            transport=_httpx2.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            results = await asyncio.gather(*(aclient.contact.get(id=i) for i in range(20)))
            assert len(results) == 20
            assert len(observed_paths) == 20
            assert {r.json()["Path"] for r in results} == {f"/v3/REST/contact/{i}" for i in range(20)}

    asyncio.run(_run())
