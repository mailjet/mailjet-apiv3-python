"""Asynchronous client, proxy resolution, stream retries, cancellation, and MockMailjetClient regression tests."""

from __future__ import annotations

import asyncio
import io
import json
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from mailjet_rest.client import AsyncClient, _httpx2
from mailjet_rest.testing import MockMailjetClient, MockResponse


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
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        captured_bodies: list[bytes] = []

        def _handler(request: Any) -> Any:
            captured_bodies.append(request.content)
            return httpx2_mod.Response(200, json={"Count": 1, "Data": []}, request=request)

        transport = httpx2_mod.MockTransport(_handler)
        async with AsyncClient(auth=("pub", "priv"), transport=transport) as aclient:
            resp = await aclient.contact.create(data=payload, headers={header_name: header_value})
            assert resp.status_code == 200

        assert len(captured_bodies) == 1
        assert json.loads(captured_bodies[0].decode("utf-8")) == payload

    asyncio.run(_run())


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
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        mock_tp = httpx2_mod.MockTransport(
            lambda req: httpx2_mod.Response(200, json={"Count": 0, "Data": []}, request=req),
        )
        async with AsyncClient(auth=("pub", "priv"), transport=mock_tp) as aclient:
            with patch.object(httpx2_mod, "AsyncHTTPTransport", return_value=mock_tp) as mock_http_tp:
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
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        mock_tp = httpx2_mod.MockTransport(
            lambda req: httpx2_mod.Response(200, json={"Count": 0, "Data": []}, request=req),
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


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_isolates_trust_env_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """PR #179 #3: AsyncClient defaults trust_env to False, rejecting ambient HTTP_PROXY and .netrc unless opted in."""
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    netrc_file = tmp_path / ".netrc"
    netrc_file.write_text("machine api.mailjet.com login netrc_user password netrc_secret\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc_file))

    async def _check_async_trust_env() -> None:
        async with AsyncClient(auth="bearer_tok_123") as async_client:
            assert async_client.session.trust_env is False
            seen_trust_env: list[bool] = []
            real_async_client = httpx2_mod.AsyncClient

            def _spy_async_client(*args: Any, **kwargs: Any) -> Any:
                seen_trust_env.append(bool(kwargs.get("trust_env", True)))
                kwargs["transport"] = httpx2_mod.MockTransport(
                    lambda req: httpx2_mod.Response(200, json={"Count": 0, "Data": []}, request=req),
                )
                return real_async_client(*args, **kwargs)

            with patch.object(httpx2_mod, "AsyncClient", side_effect=_spy_async_client):
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


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_idempotency_key_scoped_by_method_url_and_sandbox_mode() -> None:
    """PR #179 #7: AsyncClient Idempotency-Key must differ across method and target URL."""
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _check_async() -> None:
        async_keys: list[str] = []

        def _handler(request: Any) -> Any:
            async_keys.append(request.headers["Idempotency-Key"])
            return httpx2_mod.Response(200, json={"Count": 1, "Data": []}, request=request)

        transport = httpx2_mod.MockTransport(_handler)
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
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

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
                return httpx2_mod.Response(503, text="retry me", request=request)
            return httpx2_mod.Response(200, json={"OK": True}, request=request)

        transport = httpx2_mod.MockTransport(_handler)
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
def test_async_stream_retry_preserves_nonzero_initial_seek_offset(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #7: Async retry stream rewind must restore the caller's initial offset instead of forcing seek(0)."""
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

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
                raise httpx2_mod.ConnectError("transient disconnect")
            return httpx2_mod.Response(200, json={"OK": True}, request=httpx2_mod.Request("POST", kwargs["url"]))

        async with AsyncClient(auth=("pub", "priv"), max_retries=1) as aclient:
            monkeypatch.setattr(aclient.session, "request", _handler)
            resp = await aclient.contact.create(
                data={"Field": "val"},
                files={"attachment": ("slice.bin", buf, "application/octet-stream")},
            )
            assert resp.status_code == 200

        assert uploads == [b"REAL_BODY", b"REAL_BODY"]

    asyncio.run(_run())


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
                val_mock.contact.delete(id=bad_id)  # type: ignore[arg-type]


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_dry_run_async_returns_valid_json_body() -> None:
    """PR #179 #12c: Async dry_run=True mutations must return valid parseable JSON payloads without JSONDecodeError."""
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    expected = {"DryRun": True, "Count": 0, "Total": 0, "Data": [], "Messages": []}

    async def _check_async() -> None:
        async with AsyncClient(auth=("pub", "priv"), dry_run=True) as aclient:
            async_resp = await aclient.contact.create(data={"Email": "dryrun@example.com"})
            assert async_resp.status_code == 200
            assert async_resp.json() == expected

    asyncio.run(_check_async())


@pytest.mark.skipif(_httpx2 is None, reason="httpx2 is not installed")
def test_async_client_cancelled_error_propagates_and_session_recovers(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #14b: asyncio.CancelledError during transport or retry sleep must propagate and leave client reusable."""
    if _httpx2 is None:
        pytest.skip("httpx2 is not installed")
    assert _httpx2 is not None
    httpx2_mod = _httpx2

    async def _run() -> None:
        call_idx = 0

        async def _cancel_inflight(**kwargs: Any) -> Any:
            nonlocal call_idx
            call_idx += 1
            if call_idx == 1:
                raise asyncio.CancelledError
            return httpx2_mod.Response(
                200,
                json={"Recovered": True},
                request=httpx2_mod.Request("GET", kwargs["url"]),
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
                return httpx2_mod.Response(503, text="retry", request=httpx2_mod.Request("GET", kwargs["url"]))
            return httpx2_mod.Response(200, json={"OK": True}, request=httpx2_mod.Request("GET", kwargs["url"]))

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
