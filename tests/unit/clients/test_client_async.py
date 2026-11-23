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
import uuid
import warnings
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mailjet_rest.client import AsyncClient, Config, _httpx2, parse_response
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
from mailjet_rest.routes import ROUTE_MAP
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
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        captured_headers: list[str] = []

        def transport_handler(request: Any) -> Any:
            captured_headers.append(request.headers.get("Authorization", ""))
            return httpx2_mod.Response(200, json={"ok": True}, request=request)

        async with AsyncClient(auth=("super_secret_pub", "super_secret_priv")) as basic_client:
            assert isinstance(basic_client.auth, SecretAuth)
            assert basic_client.auth == ("super_secret_pub", "super_secret_priv")
            assert "super_secret" not in repr(basic_client)
            assert "Mailjet AsyncClient" in str(basic_client)
            assert "Authorization" not in basic_client.session.headers

            basic_client.session = httpx2_mod.AsyncClient(
                auth=basic_client._build_auth_and_headers()[0],
                headers=basic_client._build_auth_and_headers()[1],
                follow_redirects=False,
                transport=httpx2_mod.MockTransport(transport_handler),
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
    assert _httpx2 is not None
    httpx2_mod = _httpx2

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
            assert isinstance(transport, httpx2_mod.AsyncHTTPTransport)
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
    assert _httpx2 is not None
    httpx2_mod = _httpx2

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
            req = httpx2_mod.Request(kwargs.get("method", "GET"), kwargs.get("url", "https://api.mailjet.com"))
            return httpx2_mod.Response(200, json={"Count": 1, "Total": 1, "Data": [{"ID": 42}]}, request=req)

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
        assert isinstance(captured_kwargs["timeout"], httpx2_mod.Timeout)
        with pytest.warns(DeprecationWarning, match="parse_response"):
            assert parse_response(res_post)["Count"] == 1

        captured_kwargs.clear()

        async def mock_async_202(**kwargs: Any) -> Any:
            captured_kwargs.update(kwargs)
            req = httpx2_mod.Request(kwargs.get("method", "POST"), kwargs.get("url", "https://api.mailjet.com"))
            return httpx2_mod.Response(202, text="Accepted", request=req)

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
        client.session = None  # type: ignore[assignment]
        await client.aclose()

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_idempotency_modes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify fingerprint, uuid4, and off auto_idempotency_mode parity on AsyncClient."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        async def ok_request(**kwargs: Any) -> Any:
            captured_headers.append(dict(kwargs.get("headers", {})))
            req = httpx2_mod.Request("POST", "https://api.mailjet.com/v3/REST/contact")
            return httpx2_mod.Response(200, json={"Data": []}, request=req)

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
    assert _httpx2 is not None
    httpx2_mod = _httpx2
    ca_file = tmp_path / "custom-ca.pem"
    ca_file.write_text("dummy-ca", encoding="utf-8")

    async def _run() -> None:
        async with AsyncClient(auth=("k", "s")) as aclient:
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact", allow_redirects=True)
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await aclient.api_call("GET", "https://api.mailjet.com/v3/REST/contact", follow_redirects=True)

            # 3xx redirect audit event + warning
            req = httpx2_mod.Request("GET", "https://api.mailjet.com/v3/REST/contact")
            resp_302 = httpx2_mod.Response(302, headers={"Location": "https://evil.example.com"}, request=req)
            monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=resp_302))

            with (
                patch("mailjet_rest.client.sys.audit") as mock_audit,
                caplog.at_level(logging.WARNING),
            ):
                res = await aclient.contact.get()
            assert res.status_code == 302
            mock_audit.assert_any_call(
                "mailjet.security.unexpected_redirect",
                "https://api.mailjet.com/v3/REST/contact",
                302,
            )
            assert "redirects are disabled" in caplog.text

            # Per-call CA bundle uses isolated ephemeral transport without warning
            ephemeral_calls: list[Any] = []
            default_pool = getattr(getattr(aclient.session, "_transport", None), "_pool", None)
            default_ssl_ctx = getattr(default_pool, "_ssl_context", None)

            async def fake_ephemeral(
                _self: AsyncClient,
                _httpx2_mod: Any,
                req_verify: bool | str,
                proxies: Any,
                cert: Any,
                req_kwargs: dict[str, Any],
            ) -> Any:
                ephemeral_calls.append((req_verify, proxies, cert, req_kwargs["url"]))
                return httpx2_mod.Response(200, json={"Data": []}, request=req)

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
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        async with AsyncClient(auth=("pub_key", "priv_key"), max_retries=0) as aclient:
            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(side_effect=httpx2_mod.TimeoutException("Async read timed out")),
            )
            with pytest.raises(TimeoutError, match="Request to Mailjet API timed out"):
                await aclient.contact.get()

            for conn_exc in (
                httpx2_mod.ConnectError("Async connection refused"),
                httpx2_mod.NetworkError("Async network drop"),
                httpx2_mod.RemoteProtocolError("Async protocol reset"),
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
                req = httpx2_mod.Request("GET", "https://api.mailjet.com/v3/REST/contact")
                resp = httpx2_mod.Response(status, json={"ErrorMessage": f"err-{status}"}, request=req)
                monkeypatch.setattr(aclient.session, "request", AsyncMock(return_value=resp))
                with pytest.raises(exc_cls, match=f"err-{status}"):
                    await aclient.contact.get()

            monkeypatch.setattr(
                aclient.session,
                "request",
                AsyncMock(side_effect=httpx2_mod.HTTPError("Generic httpx2 failure")),
            )
            with pytest.raises(ApiError, match="An unexpected Mailjet API network error occurred"):
                await aclient.contact.get()

    asyncio.run(_run())


# ==========================================
# 4. Transport, Lifecycle, Retry, Copy & Concurrency Tests
# ==========================================


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_custom_transport_and_ping() -> None:
    """Verify custom httpx2 transport injection and ping() behavior on AsyncClient."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        seen_urls: list[str] = []
        seen_auths: list[str] = []
        status_queue = [200, 401, 500]

        def handler(request: Any) -> Any:
            seen_urls.append(str(request.url))
            seen_auths.append(request.headers.get("Authorization", ""))
            if not status_queue:
                raise httpx2_mod.ConnectError("simulated outage")
            return httpx2_mod.Response(status_queue.pop(0), json={"Data": []})

        transport = httpx2_mod.MockTransport(handler)
        async with AsyncClient(auth=("pub_key", "priv_key"), transport=transport, max_retries=0) as aclient:
            resp = await aclient.contact.get()
            assert resp.status_code == 200
            assert seen_auths[0].startswith("Basic ")

        # Verify AsyncClient.ping() true / auth fail / server error / connect error / SSRF fail-closed
        ping_outcomes: list[Any] = [200, 401, 503, httpx2_mod.ConnectError("network down")]

        def ping_handler(_request: Any) -> Any:
            outcome = ping_outcomes.pop(0)
            if isinstance(outcome, Exception):
                raise outcome
            return httpx2_mod.Response(outcome, json={"Data": []})

        async with AsyncClient(
            auth=("pub_key", "priv_key"),
            transport=httpx2_mod.MockTransport(ping_handler),
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


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_copy_deepcopy_isolation_and_dunder_rejection() -> None:
    """Verify __copy__ and __deepcopy__ isolate locks/sessions/caches without SecretAuth warnings."""
    assert _httpx2 is not None

    transport = _httpx2.MockTransport(lambda _r: _httpx2.Response(200, json={"Data": []}))  # type: ignore[union-attr]
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

    for bad_attr in ("_private_attr", "__nonexistent_dunder__"):
        with pytest.raises(AttributeError):
            _ = getattr(orig, bad_attr)

    asyncio.run(orig.aclose())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_retry_backoff_rewind_fast_fail_and_causes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify retries with capped Retry-After, BytesIO rewind, fast-fail errors, and PEP 3134 __cause__."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        sleep_mock = AsyncMock()
        monkeypatch.setattr(asyncio, "sleep", sleep_mock)

        # 1. Transient 503 (capped Retry-After: 120 -> 60.0) -> 429 (invalid date -> jitter) -> 200
        req = httpx2_mod.Request("POST", "https://api.mailjet.com/v3/REST/contact")
        responses = [
            httpx2_mod.Response(503, headers={"Retry-After": "120"}, request=req),
            httpx2_mod.Response(429, headers={"Retry-After": "not-a-float"}, request=req),
            httpx2_mod.Response(200, json={"Count": 1}, request=req),
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
                raise httpx2_mod.ConnectError("socket dropped mid-upload")
            return httpx2_mod.Response(200, json={"OK": True}, request=req)

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
        for fast_exc_cls in (httpx2_mod.UnsupportedProtocol, httpx2_mod.DecodingError):
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
            to_exc = httpx2_mod.TimeoutException("read timeout")
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(side_effect=to_exc))
            with pytest.raises(TimeoutError) as to_info:
                await cause_client.contact.get()
            assert to_info.value.__cause__ is to_exc

            conn_exc = httpx2_mod.ConnectError("refused")
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(side_effect=conn_exc))
            with pytest.raises(CriticalApiError) as conn_info:
                await cause_client.contact.get()
            assert conn_info.value.__cause__ is conn_exc

            resp_503 = httpx2_mod.Response(503, text="backend unavailable", request=req)
            monkeypatch.setattr(cause_client.session, "request", AsyncMock(return_value=resp_503))
            with pytest.raises(MailjetApiError) as http_info:
                await cause_client.contact.get()
            assert isinstance(http_info.value.__cause__, httpx2_mod.HTTPStatusError)

    asyncio.run(_run())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_concurrent_gather_requests() -> None:
    """Verify AsyncClient executes concurrent asyncio.gather requests safely via shared transport."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        observed_paths: list[str] = []

        def handler(request: Any) -> Any:
            observed_paths.append(request.url.path)
            return httpx2_mod.Response(200, json={"Path": request.url.path})

        async with AsyncClient(
            auth=("k", "s"),
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            results = await asyncio.gather(*(aclient.contact.get(id=i) for i in range(20)))
            assert len(results) == 20
            assert len(observed_paths) == 20
            assert {r.json()["Path"] for r in results} == {f"/v3/REST/contact/{i}" for i in range(20)}

    asyncio.run(_run())


def test_async_client_closed_placeholder_reentry_and_proxy_transport(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Cover AsyncClient closed placeholder reuse, stale re-entry, stream=True rejection, and proxy transport."""
    # AsyncClient closed placeholder session (safe even with broken SSL_CERT_FILE), stale re-entry,
    # isolated request via MockTransport, and stream=True rejection
    if _httpx2 is not None:
        httpx2_mod = _httpx2
        monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "nonexistent_conda_cacert.pem"))

        def _mock_transport_handler(request: Any) -> Any:
            return httpx2_mod.Response(200, json={"Data": []}, request=request)

        mock_tp = httpx2_mod.MockTransport(_mock_transport_handler)

        async def _check_async_edges() -> None:
            aclient = AsyncClient(auth=("pub", "priv"), transport=mock_tp)
            await aclient.aclose()
            closed_sess = aclient.session
            assert closed_sess.is_closed
            # Calling session again while already closed reuses closed placeholder when not yet disposed
            assert aclient.session is closed_sess

            stale_mock_sess = AsyncMock()
            stale_mock_sess.is_closed = False
            aclient._session = stale_mock_sess
            async with aclient as entered:
                stale_mock_sess.aclose.assert_awaited_once()
                assert entered is aclient

            with pytest.raises(ValueError, match="stream=True is not supported"):
                await entered.api_call("GET", "https://api.mailjet.com/v3/REST/contact", stream=True)

            # Isolated request branch when per-call proxies are supplied (mocked transport, zero network I/O)
            with patch.object(httpx2_mod, "AsyncHTTPTransport", return_value=mock_tp) as mock_http_tp:
                iso_resp = await entered._execute_request(
                    "GET",
                    "https://api.mailjet.com/v3/REST/contact",
                    {},
                    None,
                    None,
                    5,
                    proxies={"https": "https://localhost:8443"},
                )
            assert iso_resp.status_code == 200
            assert mock_http_tp.call_args.kwargs["proxy"] == "https://localhost:8443"

        asyncio.run(_check_async_edges())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_routes_ssrf_multipart_retry_allowlist_and_gather(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify AsyncClient new routes, concurrent gather, per-call SSRF, multipart guard, and method retry gate."""
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        observed: list[tuple[str, str]] = []

        def handler(request: Any) -> Any:
            observed.append((request.method, str(request.url)))
            return httpx2_mod.Response(200, json={"Count": 1, "Total": 1, "Data": [{"ID": 1}]})

        async with AsyncClient(
            auth=("pub_key", "priv_key"),
            transport=httpx2_mod.MockTransport(handler),
            max_retries=0,
        ) as aclient:
            # Per-call SSRF blocked on AsyncClient.api_call
            with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
                await aclient.api_call("GET", "https://evil.example/exfiltrate")

            # Multipart CRLF filename blocked before network send
            with pytest.raises(ValueError, match="Multipart file filename contains forbidden CRLF or NUL"):
                await aclient.api_call(
                    "POST",
                    "https://api.mailjet.com/v1/data/images",
                    files={"file": ("evil\r\n.png", io.BytesIO(b"png"), "image/png")},
                )

            # Concurrent asyncio.gather across new OpenAPI & v4 routes
            payload = MappingProxyType({"Messages": [{"From": {"Email": "a@b.com"}, "To": [{"Email": "c@d.com"}]}]})
            res_list = await asyncio.gather(
                aclient.send_v31.create(data=payload),
                aclient.v1_templates.get(),
                aclient.template_contents_publish.create(id=7, data={}),
                aclient.template_contents_lock.create(id=7, data={}),
                aclient.template_contents_unlock.create(id=7, data={}),
                aclient.data_images_by_type.update(id="img-1", action_id="thumbnail", data=b"thumb"),
                aclient.contacts.delete(id=55),
            )
            assert all(r.status_code == 200 for r in res_list)
            assert set(observed) == {
                ("POST", "https://api.mailjet.com/v3.1/send"),
                ("GET", "https://api.mailjet.com/v1/REST/templates"),
                ("POST", "https://api.mailjet.com/v1/REST/templates/7/contents/publish"),
                ("POST", "https://api.mailjet.com/v1/REST/templates/7/contents/lock"),
                ("POST", "https://api.mailjet.com/v1/REST/templates/7/contents/unlock"),
                ("PUT", "https://api.mailjet.com/v1/data/images/img-1/thumbnail"),
                ("DELETE", "https://api.mailjet.com/v4/contacts/55"),
            }

        # Non-allowlisted HTTP method never retries even when max_retries > 0
        req = httpx2_mod.Request("TRACE", "https://api.mailjet.com/v3/REST/contact")
        resp_503 = httpx2_mod.Response(503, text="upstream busy", request=req)
        trace_method: Any = "TRACE"
        async with AsyncClient(auth=("pub_key", "priv_key"), max_retries=3) as retry_client:
            mock_req = AsyncMock(return_value=resp_503)
            monkeypatch.setattr(retry_client.session, "request", mock_req)
            with pytest.raises(MailjetApiError):
                await retry_client.api_call(trace_method, "https://api.mailjet.com/v3/REST/contact")
            assert mock_req.await_count == 1

    asyncio.run(_run())


def test_async_client_form_mapping_payload_uses_data_not_content() -> None:
    """Non-JSON Mapping payloads on AsyncClient must use form data= rather than crashing content=."""
    if _httpx2 is None:
        pytest.skip("httpx2 not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    captured: list[tuple[str, bytes]] = []

    def handler(request: Any) -> Any:
        captured.append((request.headers.get("content-type", ""), request.read()))
        return httpx2_mod.Response(200, json={"Data": [], "Count": 0})

    async def _run() -> None:
        async with AsyncClient(
            auth=("pub_key", "priv_key"),
            transport=httpx2_mod.MockTransport(handler),
        ) as client:
            resp = await client.contact.create(
                data={"Name": "Alice"},
                headers={"content-type": "application/x-www-form-urlencoded"},
            )
            assert resp.status_code == 200

    asyncio.run(_run())
    assert len(captured) == 1
    assert "application/x-www-form-urlencoded" in captured[0][0]
    assert b"Name=Alice" in captured[0][1]


def test_async_client_available_endpoints_and_did_you_mean() -> None:
    """Verify AsyncClient.available_endpoints and AttributeError 'Did you mean' suggestion."""
    if _httpx2 is not None:

        async def _check_async_dx() -> None:
            async with AsyncClient(auth=("pub_key", "priv_key")) as aclient:
                assert aclient.available_endpoints == tuple(sorted(ROUTE_MAP))
                with pytest.raises(
                    AttributeError,
                    match=r"has no endpoint or attribute 'snd'\. Did you mean 'send'\?",
                ):
                    _ = aclient.snd

        asyncio.run(_check_async_dx())
