"""Offline loopback TLS 1.2+ and HTTP parity integration tests for AsyncClient and AsyncEndpoint."""

from __future__ import annotations

import asyncio
import copy
import io
import logging
import types
from pathlib import Path
from typing import Any, cast

import pytest

from mailjet_rest import (
    ApiError,
    ApiRateLimitError,
    AsyncClient,
    Config,
    CriticalApiError,
    DoesNotExistError,
    MailjetApiError,
    MailjetAuthError,
    MailjetNetworkError,
    TimeoutError as MailjetTimeoutError,
    ValidationError,
)
from mailjet_rest.client import BaseClient, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.errors import MAX_ERROR_BODY_CHARS
from mailjet_rest.utils.retry import run_async_with_retries
from mailjet_rest.utils.transport_security import build_httpx2_transport, coerce_httpx2_timeout
from tests.integration.local_loopback._servers import _RecordingHTTPSServer, unused_loopback_port


pytestmark = pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed.")


def test_async_retry_helpers_and_transport_builders(loopback_servers: dict[str, Any]) -> None:
    """Exercise async retry helpers (run_async_with_retries) and httpx2 transport/timeout builders."""
    assert _httpx2 is not None
    ca_path: Path = loopback_servers["ca_path"]
    key_path: Path = loopback_servers["key_path"]
    combined_pem: Path = loopback_servers["combined_pem"]

    # Transport & timeout builders
    t_tuple = coerce_httpx2_timeout(_httpx2, (1.5, 4.5))
    assert t_tuple.connect == 1.5
    assert t_tuple.read == 4.5
    assert coerce_httpx2_timeout(_httpx2, None) is None
    assert (
        build_httpx2_transport(_httpx2, str(ca_path), pool_connections=2, pool_maxsize=4, cert=combined_pem) is not None
    )
    assert (
        build_httpx2_transport(
            _httpx2,
            str(ca_path),
            pool_connections=2,
            pool_maxsize=4,
            cert=(str(ca_path), str(key_path)),
        )
        is not None
    )

    log = logging.getLogger("test_async_retry")

    async def _check_async_paths() -> None:
        with pytest.raises(ValueError, match="non-negative integer"):
            await run_async_with_retries(
                lambda: asyncio.sleep(0),
                _httpx2,
                method="GET",
                url="https://127.0.0.1/",
                raw_retries=-1,
                max_retries_limit=5,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({429}),
                max_delay=1.0,
                data=None,
                files=None,
                log=log,
            )

        async def _unsupported() -> Any:
            assert _httpx2 is not None
            raise _httpx2.UnsupportedProtocol("bad proto")

        with pytest.raises(_httpx2.UnsupportedProtocol):
            await run_async_with_retries(
                _unsupported,
                _httpx2,
                method="GET",
                url="https://127.0.0.1/",
                raw_retries=2,
                max_retries_limit=5,
                allowed_methods=("GET",),
                transient_status_codes=frozenset({429}),
                max_delay=1.0,
                data=None,
                files=None,
                log=log,
            )

        class _UnclosedResp:
            def __init__(self, status: int) -> None:
                self.status_code = status
                self.headers = {"Retry-After": "0"}
                self.is_closed = False
                self.closed_called = False

            async def aclose(self) -> None:
                self.closed_called = True
                self.is_closed = True

        first_resp = _UnclosedResp(429)
        second_resp = _UnclosedResp(200)
        calls = 0

        async def _flaky_unclosed() -> Any:
            nonlocal calls
            calls += 1
            return first_resp if calls == 1 else second_resp

        res = await run_async_with_retries(
            _flaky_unclosed,
            _httpx2,
            method="GET",
            url="https://127.0.0.1/",
            raw_retries=2,
            max_retries_limit=5,
            allowed_methods=("GET",),
            transient_status_codes=frozenset({429}),
            max_delay=1.0,
            data=None,
            files=None,
            log=log,
        )
        assert res is second_resp
        assert first_resp.closed_called is True

        # Non-idempotent POST omitted from allowed_methods does NOT retry
        post_calls = 0

        async def _post_429() -> Any:
            nonlocal post_calls
            post_calls += 1
            return _UnclosedResp(429)

        post_res = await run_async_with_retries(
            _post_429,
            _httpx2,
            method="POST",
            url="https://127.0.0.1/",
            raw_retries=3,
            max_retries_limit=5,
            allowed_methods=("GET",),
            transient_status_codes=frozenset({429}),
            max_delay=1.0,
            data=None,
            files=None,
            log=log,
        )
        assert post_res.status_code == 429
        assert post_calls == 1

    asyncio.run(_check_async_paths())


def test_async_client_and_endpoint_real_https_and_http_integration(
    loopback_servers: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Exercise AsyncClient and AsyncEndpoint parity over real loopback TLS 1.2+ and HTTP sockets."""
    assert _httpx2 is not None
    https_url: str = loopback_servers["https_url"]
    http_url: str = loopback_servers["http_url"]
    ca_path: Path = loopback_servers["ca_path"]
    key_path: Path = loopback_servers["key_path"]
    combined_pem: Path = loopback_servers["combined_pem"]
    untrusted_ca: Path = loopback_servers["untrusted_ca"]
    https_srv: _RecordingHTTPSServer = loopback_servers["https_server"]

    dead_proxy = f"http://127.0.0.1:{unused_loopback_port()}"
    monkeypatch.setenv("HTTPS_PROXY", dead_proxy)
    monkeypatch.setenv("https_proxy", dead_proxy)

    async def _run() -> None:
        assert _httpx2 is not None
        https_srv.recorded_requests.clear()
        https_srv.flaky_calls = 0
        https_srv.flaky_503_calls = 0

        # Warning when auth=None + unused client aclose/close
        with pytest.warns(UserWarning, match="without 'auth'"):
            no_auth_client = AsyncClient(config=Config(api_url=https_url, verify=ca_path))
        await no_auth_client.aclose()

        unused_close_client = AsyncClient(auth="tok", config=Config(api_url=https_url, verify=ca_path))
        await unused_close_client.close()

        # Basic Auth (SecretAuth) over TLS 1.2+ + trust_env=False + introspection + copy/deepcopy + CRUD + stream + retries
        async with AsyncClient(
            auth=("pub", "priv"),
            config=Config(
                api_url=https_url,
                verify=ca_path,
                max_retries=3,
                trust_env=False,
                enable_security_audit=True,
            ),
        ) as ac:
            # Introspection & wrappers
            assert "contact" in ac.available_endpoints
            assert "AsyncClient" in repr(ac)
            assert "Mailjet AsyncClient" in str(ac)
            assert "contact" in dir(ac)
            assert "AsyncEndpoint" in repr(ac.contact)
            assert ac.contact._resolve_registry_route(https_url.rstrip("/"), "v3", None, None)[0].endswith(
                "/REST/contact"
            )
            assert ac.contact._resolve_dynamic_route(https_url.rstrip("/"), "v3", None, None)[0].endswith(
                "/REST/contact"
            )
            assert ac.contact._build_headers()["Content-Type"] == "application/json"
            assert AsyncEndpoint._cast_query_param(0, "7") == 7
            with pytest.raises(ApiError):
                BaseClient._handle_api_error(RuntimeError("boom"))

            assert await ac.ping() is True

            # Endpoint caching & private / typo attribute checks
            cached_contact = ac.contact
            second_contact = ac.contact
            assert cached_contact is second_contact
            assert ac._resolve_endpoint("contact", AsyncEndpoint) is ac.contact
            with pytest.raises(AttributeError):
                _ = ac._private_attr
            with pytest.raises(AttributeError):
                ac._validate_endpoint_name("_private_attr")
            with pytest.raises(AttributeError, match="Did you mean 'send'"):
                _ = ac.snd

            # Shallow & deep copy
            ac_shallow = copy.copy(ac)
            ac_deep = copy.deepcopy(ac)
            try:
                assert ac_shallow._session is None
                assert ac_deep._session is None
                assert await ac_shallow.ping() is True
                assert await ac_deep.ping() is True
            finally:
                await ac_shallow.aclose()
                await ac_deep.close()

            # Route variants: v4, v1, action_id, missing id/action_id, deprecated routes, ambiguous templates
            assert (await ac.contacts.get()).json()["path"] == "/v4/contacts"
            assert (await ac.tokens.get()).json()["path"] == "/v1/REST/tokens"
            assert (await ac.template_content_by_type.get(id=5, action_id="html")).json()["path"] == (
                "/v1/REST/templates/5/contents/types/html"
            )
            with pytest.raises(ValueError, match="requires an 'id'"):
                await ac.template_detailcontent.get()
            with pytest.raises(ValueError, match="requires an 'action_id'"):
                await ac.template_content_by_type.get(id=5)

            with pytest.warns(DeprecationWarning, match="deprecated"):
                assert (await ac.newsletter.get()).status_code == 200
            with pytest.warns(DeprecationWarning, match="Ambiguity"):
                assert (await ac.templates.get()).status_code == 200
            assert (await ac.SEND.create(data={"k": "v"})).json()["path"] == "/v3/send"
            assert (await ac.customjob_csvdata.get(id=7)).json()["path"] == "/v3/DATA/customjob/7/CSVData/text:plain"

            # Filter dropping None query values
            ok_resp = await ac.contact.get(filters={"Keep": "yes", "Drop": None})
            assert ok_resp.status_code == 200
            assert https_srv.recorded_requests[-1]["query"] == {"Keep": ["yes"]}

            # Async CRUD verbs (+json, MappingProxyType, list payload, form-urlencoded, multipart files, deprecated enc)
            r_plus_json = await ac.contact.create(
                headers={"content-type": "application/vnd.api+json"},
                data=types.MappingProxyType({"Email": "proxy-async@example.com"}),
            )
            assert r_plus_json.status_code == 201
            assert "idempotency-key" in https_srv.recorded_requests[-1]["headers"]

            r_explicit_idem = await ac.contact.create(
                headers={"Idempotency-Key": "async-manual-key-1"},
                data=[{"Email": "list-async@example.com"}],
            )
            assert r_explicit_idem.status_code == 201
            assert https_srv.recorded_requests[-1]["headers"]["idempotency-key"] == "async-manual-key-1"

            assert (
                await ac.contact.create(
                    headers={"Content-Type": "application/x-www-form-urlencoded"},
                    data=types.MappingProxyType({"Field": "Value"}),
                )
            ).status_code == 201

            r_file = await ac.data_images.create(
                files={"file": ("logo.png", io.BytesIO(b"\x89PNG\r\n\x1a\n"), "image/png")},
            )
            assert r_file.status_code == 201
            assert "multipart/form-data" in https_srv.recorded_requests[-1]["headers"]["content-type"]

            r_file_txt = await ac.data_images.create(
                headers={"X-Tag": "v1", "Content-Type": "text/plain"},
                files={"file": ("note.txt", io.BytesIO(b"hello"), "text/plain")},
            )
            assert r_file_txt.status_code == 201

            with pytest.warns(DeprecationWarning, match="deprecated"):
                r_enc = await ac.contact.create(
                    data={"Email": "café-async@example.com"},
                    ensure_ascii=False,
                    data_encoding="utf-8",
                )
            assert r_enc.status_code == 201
            with pytest.warns(DeprecationWarning, match="deprecated"):
                assert (await ac.contact.create(data="raw-string", ensure_ascii=True)).status_code == 201

            upd_resp = await ac.contact.update(id=42, data={"Name": "AsyncPut"})
            del_resp = await ac.contact.delete(id=42)
            assert upd_resp.status_code == 200
            assert del_resp.status_code == 204

            with pytest.raises(ValueError, match="non-empty"):
                await ac.contact.delete(id="")

            # 204, 205, 304, 302 (redirects never followed)
            assert (await ac.nocontent.get()).status_code == 204
            assert (await ac.resetcontent.get()).status_code == 205
            assert (await ac.notmodified.get()).status_code == 304
            assert (await ac.redirect.get()).status_code == 302

            # Async stream pagination: max_items=0, natural termination, max_items limit, empty, malformed pages, validation
            assert [item["ID"] async for item in ac.contact.stream(chunk_size=2, max_items=0)] == []
            assert [item["ID"] async for item in ac.contact.stream(chunk_size=2)] == [1, 2, 3]
            assert [item["ID"] async for item in ac.contact.stream(chunk_size=2, max_items=2)] == [1, 2]
            assert [item["ID"] async for item in ac.contact.stream(chunk_size=2, filters={"empty_stream": "1"})] == []
            assert [item["ID"] async for item in ac.contact.stream(chunk_size=2, filters={"no_data": "1"})] == []
            with pytest.raises(MailjetApiError, match="Malformed JSON"):
                _ = [item async for item in ac.contact.stream(chunk_size=2, filters={"bad_json": "1"})]
            with pytest.raises(MailjetApiError, match="Expected JSON object"):
                _ = [item async for item in ac.contact.stream(chunk_size=2, filters={"list_json": "1"})]
            with pytest.raises(MailjetApiError, match="Expected 'Data' list"):
                _ = [item async for item in ac.contact.stream(chunk_size=2, filters={"bad_data": "1"})]
            with pytest.raises(ValueError, match="strictly positive"):
                _ = [item async for item in ac.contact.stream(chunk_size=0)]
            with pytest.raises(ValueError, match="GET requests only"):
                _ = [item async for item in ac.contact.stream(method="POST")]

            # Real socket 503 retry recovery on GET
            r_503 = await ac.flaky503.get()
            assert r_503.status_code == 200
            assert https_srv.flaky_503_calls == 2

            # One-shot StringIO stream reader + RFC-2822 HTTP-date Retry-After retry recovery on POST
            s_io = io.StringIO("async-string-payload")
            flaky_resp = await ac.api_call(
                "POST",
                f"{https_url}v3/REST/flaky",
                headers={"X-Use-Http-Date": "1"},
                data=s_io,  # type: ignore[arg-type]
            )
            assert flaky_resp.status_code == 201
            assert flaky_resp.json()["body_text"] == "async-string-payload"

            # Seekable BytesIO stream rewind across 429 retries
            https_srv.flaky_calls = 0
            bio = io.BytesIO(b"rewindable-async-body")
            flaky_bio_resp = await ac.api_call("POST", f"{https_url}v3/REST/flaky", data=cast("Any", bio))
            assert flaky_bio_resp.status_code == 201
            assert flaky_bio_resp.json()["body_text"] == "rewindable-async-body"

            # stream=True rejection & redirect rejection
            with pytest.raises(ValueError, match="stream=True is not supported"):
                await ac.api_call("GET", f"{https_url}v3/REST/contact", stream=True)
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await ac.contact.get(allow_redirects=True)
            with pytest.raises(ValueError, match="Redirects are strictly disabled"):
                await ac.contact.get(follow_redirects=True)

            # TimeoutError over real socket + timeout validation & config fallback
            with pytest.raises(MailjetTimeoutError) as to_exc:
                await ac.api_call("GET", f"{https_url}v3/REST/slow", timeout=0.05)
            assert isinstance(to_exc.value, MailjetNetworkError)
            assert isinstance(to_exc.value, TimeoutError)

            with pytest.raises(ValueError, match="strictly positive"):
                await ac.contact.get(timeout=-1)

            ac.config.timeout = -5
            with pytest.raises(ValueError, match="strictly positive"):
                await ac.contact.get()
            assert ac.config.timeout > 0

        # Closed AsyncClient session placeholder & re-entry with stale open session cleanup
        closed_placeholder = ac.session
        assert ac.session is closed_placeholder
        assert closed_placeholder.auth is None
        assert dict(closed_placeholder.headers) == {}
        ac.session = None

        # Simulate stale unclosed session when re-entering __aenter__
        ac.session = _httpx2.AsyncClient(follow_redirects=False, trust_env=False)
        async with ac as reopened_ac:
            assert await reopened_ac.ping() is True

        # Default CA bundle (verify=True) and untrusted CA must fail TLS verification closed
        async with AsyncClient(auth=("pub", "priv"), api_url=https_url, verify=True, max_retries=0) as default_ca_ac:
            with pytest.raises(CriticalApiError):
                await default_ca_ac.contact.get()
        async with AsyncClient(
            auth=("pub", "priv"), api_url=https_url, verify=untrusted_ca, max_retries=0
        ) as bad_ca_ac:
            with pytest.raises(CriticalApiError):
                await bad_ca_ac.contact.get()

        # Isolated transport success (config untrusted_ca overridden by per-call valid ca_path) + custom client certs + proxy
        async with AsyncClient(
            auth="bearer_tok",
            config=Config(api_url=https_url, verify=untrusted_ca, max_retries=0),
        ) as iso_ac:
            ok_iso = await iso_ac.api_call("GET", f"{https_url}v3/REST/contact", verify=ca_path)
            assert ok_iso.status_code == 200

            ok_cert_pair = await iso_ac.api_call(
                "GET",
                f"{https_url}v3/REST/contact",
                verify=ca_path,
                cert=(str(ca_path), str(key_path)),
            )
            assert ok_cert_pair.status_code == 200

            ok_cert_single = await iso_ac.api_call(
                "GET",
                f"{https_url}v3/REST/contact",
                verify=ca_path,
                cert=combined_pem,
            )
            assert ok_cert_single.status_code == 200

            # Unencrypted HTTP proxy warning + ProxyError/ConnectError -> CriticalApiError
            with pytest.warns(UserWarning, match="Unencrypted HTTP proxy"):
                with pytest.raises(CriticalApiError):
                    await iso_ac.api_call(
                        "GET",
                        f"{https_url}v3/REST/contact",
                        verify=ca_path,
                        proxies={"https": dead_proxy},
                    )

        # Invalid auth (401) + ping() returning False on 503
        async with AsyncClient(
            auth=("invalid", "invalid"),
            config=Config(api_url=https_url, verify=ca_path, max_retries=0),
        ) as bad_auth_ac:
            with pytest.raises(MailjetAuthError) as exc_401:
                await bad_auth_ac.contact.get()
            assert exc_401.value.status_code == 401

        async with AsyncClient(
            auth="fail_ping",
            config=Config(api_url=https_url, verify=ca_path, max_retries=0),
        ) as fail_ping_ac:
            assert await fail_ping_ac.ping() is False

        # dry_run=True and auto_idempotency_mode uuid4 / off
        async with AsyncClient(
            auth="bearer_tok",
            config=Config(api_url=https_url, verify=ca_path, dry_run=True, auto_idempotency_mode="off"),
        ) as dry_ac:
            pre_count = len(https_srv.recorded_requests)
            dry_resp = await dry_ac.contact.create(data={"Email": "dry-async@example.com"})
            assert dry_resp.status_code == 200
            assert dry_resp.json()["DryRun"] is True
            assert len(https_srv.recorded_requests) == pre_count

        async with AsyncClient(
            auth="bearer_tok",
            config=Config(api_url=https_url, verify=ca_path, auto_idempotency_mode="uuid4", max_retries=0),
        ) as uuid_ac:
            assert (await uuid_ac.contact.create(data={"Email": "u-async@example.com"})).status_code == 201
            assert len(https_srv.recorded_requests[-1]["headers"]["idempotency-key"]) == 36

        async with AsyncClient(
            auth="bearer_tok",
            config=Config(api_url=https_url, verify=ca_path, auto_idempotency_mode="off", max_retries=0),
        ) as off_ac:
            assert (await off_ac.contact.create(data={"Email": "off-async@example.com"})).status_code == 201
            assert "idempotency-key" not in https_srv.recorded_requests[-1]["headers"]

        # 429 retry exhaustion + HTTP status/error body mapping over async sockets
        async with AsyncClient(
            auth="bearer_tok",
            config=Config(api_url=https_url, verify=ca_path, max_retries=1),
        ) as err_ac:
            with pytest.raises(ApiRateLimitError) as rate_exc:
                await err_ac.always429.get()
            assert rate_exc.value.status_code == 429

            with pytest.raises(MailjetAuthError) as auth_exc:
                await err_ac.forbidden.get()
            assert auth_exc.value.status_code == 403
            assert "Forbidden action" in str(auth_exc.value)

            with pytest.raises(DoesNotExistError) as not_found_exc:
                await err_ac.notfound.get()
            assert not_found_exc.value.status_code == 404

            with pytest.raises(MailjetApiError) as err500_exc:
                await err_ac.err500.get()
            assert err500_exc.value.status_code == 500

            with pytest.raises(ValidationError) as list_exc:
                await err_ac.badreqlist.get()
            assert "list-level-error" in str(list_exc.value)

            with pytest.raises(ValidationError) as empty_exc:
                await err_ac.badreqempty.get()
            assert empty_exc.value.response_body == ""

            with pytest.raises(ValidationError) as big_exc:
                await err_ac.badreqbig.get()
            assert big_exc.value.response_body.endswith("...[truncated]")
            assert len(big_exc.value.response_body) < MAX_ERROR_BODY_CHARS + 50

            with pytest.raises(ValidationError) as info_exc:
                await err_ac.badreqinfo.get()
            assert "Schema mismatch" in info_exc.value.response_body

        # Dead loopback socket -> CriticalApiError (MailjetNetworkError), with and without retries
        dead_url = f"https://127.0.0.1:{unused_loopback_port()}/"
        async with AsyncClient(auth=("pub", "priv"), api_url=dead_url, verify=ca_path, max_retries=1) as dead_ac:
            with pytest.raises(CriticalApiError) as conn_exc:
                await dead_ac.contact.get()
            assert isinstance(conn_exc.value, MailjetNetworkError)

        # warn_unclosed ResourceWarning + uninitialized AsyncClient.__new__
        uninit_ac = AsyncClient.__new__(AsyncClient)
        uninit_ac._warn_if_unclosed()

        warn_ac = AsyncClient(auth="bearer_tok", api_url=https_url, verify=ca_path, warn_unclosed=True)
        _ = warn_ac.session
        with pytest.warns(ResourceWarning, match="Unclosed Mailjet AsyncClient"):
            warn_ac._warn_if_unclosed()
        await warn_ac.aclose()

        # Plain HTTP loopback AsyncClient
        async with AsyncClient(auth=("pub", "priv"), api_url=http_url, max_retries=0) as http_ac:
            assert await http_ac.ping() is True
            assert (await http_ac.contact.create(data={"Email": "http-async@example.com"})).status_code == 201

    asyncio.run(_run())
