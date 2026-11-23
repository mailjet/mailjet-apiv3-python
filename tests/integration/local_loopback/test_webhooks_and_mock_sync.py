"""Offline loopback HTTP webhook verification and MockMailjetClient integration tests (sync)."""

from __future__ import annotations

import time
import types

import pytest
import requests

from mailjet_rest import (
    ApiRateLimitError,
    MailjetApiError,
    MockMailjetClient,
    ValidationError,
    verify_webhook_signature,
)
from mailjet_rest.testing import MockEndpoint, MockResponse, _MockPingResult, _MockStreamIterator
from tests.integration.local_loopback._servers import (
    _WEBHOOK_SECRET,
    _WebhookHTTPServer,
    _sign_webhook_payload,
)


def test_webhook_loopback_http_sync_verification(webhook_server: tuple[str, _WebhookHTTPServer]) -> None:
    """Verify signed and tampered Mailjet webhook HTTP POST requests over real loopback sockets."""
    import json

    url, server = webhook_server
    server.verified_requests.clear()
    server.rejected_requests.clear()

    now = int(time.time())
    payload = json.dumps({"event": "sent", "time": now, "MessageID": 987654321}).encode("utf-8")
    raw_sig = _sign_webhook_payload(payload, _WEBHOOK_SECRET)
    ts_sig = _sign_webhook_payload(payload, _WEBHOOK_SECRET, timestamp_unix=now, signed_timestamp=True)

    with requests.Session() as session:
        session.trust_env = False

        # 1. Valid raw-payload HMAC (signed_timestamp=False)
        resp_raw = session.post(url, data=payload, headers={"X-Mailjet-Signature": raw_sig}, timeout=5)
        assert resp_raw.status_code == 200
        assert resp_raw.json() == {"verified": True}

        # 2. Valid "sha256=<UPPERCASE_HEX>" prefix normalization over HTTP
        resp_prefixed = session.post(
            url,
            data=payload,
            headers={"X-Mailjet-Signature": f"sha256={raw_sig.upper()}"},
            timeout=5,
        )
        assert resp_prefixed.status_code == 200
        assert resp_prefixed.json() == {"verified": True}

        # 3. Valid timestamp_unix inside max_age_seconds window (raw and signed_timestamp=True)
        resp_window = session.post(
            url,
            data=payload,
            headers={
                "X-Mailjet-Signature": raw_sig,
                "X-Mailjet-Timestamp": str(now - 30),
                "X-Max-Age": "300",
            },
            timeout=5,
        )
        assert resp_window.status_code == 200

        resp_signed_ts = session.post(
            url,
            data=payload,
            headers={
                "X-Mailjet-Signature": ts_sig,
                "X-Mailjet-Timestamp": str(now),
                "X-Verify-Mode": "signed-ts",
            },
            timeout=5,
        )
        assert resp_signed_ts.status_code == 200

        # 4. Stale/expired and far-future timestamps outside max_age_seconds -> HTTP 401
        resp_expired = session.post(
            url,
            data=payload,
            headers={
                "X-Mailjet-Signature": raw_sig,
                "X-Mailjet-Timestamp": str(now - 600),
                "X-Max-Age": "300",
            },
            timeout=5,
        )
        assert resp_expired.status_code == 401
        assert resp_expired.json() == {"verified": False}

        resp_future = session.post(
            url,
            data=payload,
            headers={
                "X-Mailjet-Signature": raw_sig,
                "X-Mailjet-Timestamp": str(now + 600),
                "X-Max-Age": "300",
            },
            timeout=5,
        )
        assert resp_future.status_code == 401

        # 5. Tampered timestamp under signed_timestamp=True -> HTTP 401
        resp_tampered_ts = session.post(
            url,
            data=payload,
            headers={
                "X-Mailjet-Signature": ts_sig,
                "X-Mailjet-Timestamp": str(now - 1),
                "X-Verify-Mode": "signed-ts",
            },
            timeout=5,
        )
        assert resp_tampered_ts.status_code == 401

        # 6. Missing timestamp_unix when signed_timestamp=True -> ValueError -> HTTP 400
        resp_missing_ts = session.post(
            url,
            data=payload,
            headers={"X-Mailjet-Signature": ts_sig, "X-Verify-Mode": "signed-ts"},
            timeout=5,
        )
        assert resp_missing_ts.status_code == 400
        assert "timestamp_unix is required" in resp_missing_ts.json()["error"]

        # 7. Tampered payload bytes -> HTTP 401
        tampered_payload = payload.replace(b"sent", b"open")
        resp_tampered_body = session.post(
            url,
            data=tampered_payload,
            headers={"X-Mailjet-Signature": raw_sig},
            timeout=5,
        )
        assert resp_tampered_body.status_code == 401

    assert len(server.verified_requests) == 4
    assert server.verified_requests[0]["payload"] == payload
    assert len(server.rejected_requests) == 5


def test_webhook_signature_boundaries_and_validation_errors() -> None:
    """Exercise all verify_webhook_signature validation branches, max_age=0 boundary, and surrogate handling."""
    payload = b'{"event":"bounce","MessageID":42}'
    raw_sig = _sign_webhook_payload(payload, _WEBHOOK_SECRET)

    # Direct signature normalization with "sha256=<UPPERCASE_HEX>" and surrounding whitespace
    assert verify_webhook_signature(payload, f"  sha256={raw_sig.upper()} \t\n", _WEBHOOK_SECRET) is True

    # max_age_seconds=0 exact boundary (retry once if wall-clock second rolls over mid-call)
    verified_zero_age = False
    for _ in range(2):
        ts_now = int(time.time())
        result = verify_webhook_signature(payload, raw_sig, _WEBHOOK_SECRET, timestamp_unix=ts_now, max_age_seconds=0)
        if int(time.time()) == ts_now:
            verified_zero_age = result
            break
    assert verified_zero_age is True

    stale_by_one = int(time.time()) - 1
    assert (
        verify_webhook_signature(payload, raw_sig, _WEBHOOK_SECRET, timestamp_unix=stale_by_one, max_age_seconds=0)
        is False
    )

    # Lone UTF-16 surrogates in signature_header or webhook_secret trigger UnicodeEncodeError -> False
    assert verify_webhook_signature(payload, "\ud800", _WEBHOOK_SECRET) is False
    assert verify_webhook_signature(payload, raw_sig, "secret-\ud800") is False

    # Empty or whitespace-only webhook_secret -> ValueError
    for bad_secret in ("", "   \t\n "):
        with pytest.raises(ValueError, match="webhook_secret must be a non-empty string"):
            verify_webhook_signature(payload, raw_sig, bad_secret)

    # Type validation errors
    with pytest.raises(TypeError, match="payload_bytes must be bytes"):
        verify_webhook_signature("not-bytes", raw_sig, _WEBHOOK_SECRET)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="payload_bytes must be bytes"):
        verify_webhook_signature(bytearray(payload), raw_sig, _WEBHOOK_SECRET)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="signature_header must be str"):
        verify_webhook_signature(payload, b"abc", _WEBHOOK_SECRET)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="signature_header must be str"):
        verify_webhook_signature(payload, None, _WEBHOOK_SECRET)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="webhook_secret must be str"):
        verify_webhook_signature(payload, raw_sig, b"secret")  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="webhook_secret must be str"):
        verify_webhook_signature(payload, raw_sig, None)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match="signed_timestamp must be bool"):
        verify_webhook_signature(payload, raw_sig, _WEBHOOK_SECRET, signed_timestamp=1)  # type: ignore[arg-type]

    for bad_ts in (True, False, "1700000000", 1700000000.5):
        with pytest.raises(TypeError, match="timestamp_unix must be int or None"):
            verify_webhook_signature(payload, raw_sig, _WEBHOOK_SECRET, timestamp_unix=bad_ts)  # type: ignore[arg-type]

    for bad_max_age in (-1, True, False, "300", 300.0):
        with pytest.raises(ValueError, match="max_age_seconds must be a non-negative integer"):
            verify_webhook_signature(
                payload,
                raw_sig,
                _WEBHOOK_SECRET,
                max_age_seconds=bad_max_age,  # type: ignore[arg-type]
            )

    with pytest.raises(ValueError, match="timestamp_unix is required when signed_timestamp=True"):
        verify_webhook_signature(payload, raw_sig, _WEBHOOK_SECRET, timestamp_unix=None, signed_timestamp=True)


def test_mock_mailjet_client_sync_workflow() -> None:
    """Exercise full sync workflow on MockMailjetClient, MockEndpoint, and MockResponse."""
    with MockMailjetClient() as mock:
        direct_res = mock.create(data={"Email": "pilot@example.com"})
        assert direct_res == {"Status": "success", "StatusCode": 200}

        contact_ep = mock.contact
        assert isinstance(contact_ep, MockEndpoint)

        get_res = contact_ep.get(
            id=42, filters={"Limit": 5}, action_id="manage", headers={"X-Trace": "sync"}, timeout=2.0
        )
        assert isinstance(get_res, MockResponse)
        assert get_res.status_code == 200
        get_res.raise_for_status()

        # MockResponse.json() returns an isolated shallow copy
        json_copy = get_res.json()
        assert json_copy == {"Status": "success", "StatusCode": 200, "Count": 0, "Total": 0, "Data": []}
        json_copy["Status"] = "mutated"
        json_copy["Injected"] = True
        assert get_res.json()["Status"] == "success"
        assert "Injected" not in get_res.json()

        create_res = mock.send_v31.create(data={"Messages": [{"Subject": "Sync"}]})
        assert create_res.status_code == 200

        proxy_payload = types.MappingProxyType({"IsExcludedFromCampaigns": True})
        update_res = mock.contact.update(id=42, data=proxy_payload, headers={"X-Update": "1"}, extra_flag="yes")
        assert update_res.status_code == 200

        delete_res = mock.contact.delete(id=42, action_id="purge")
        assert delete_res.status_code == 200

        call_res = mock.contact("GET", filters={"Limit": 5})
        assert call_res.status_code == 200

        assert list(mock.contact.stream(filters={"IsExcludedFromCampaigns": False}, chunk_size=25, max_items=50)) == []

        with pytest.raises(AttributeError, match="_hidden"):
            _ = mock._hidden

    # Verify recorded payloads and MappingProxyType conversion
    assert mock.sent_requests[0] == {"data": {"Email": "pilot@example.com"}}
    assert mock.sent_requests[1]["method"] == "GET"
    assert mock.sent_requests[1]["filters"] == {"Limit": 5}
    assert mock.sent_requests[1]["headers"] == {"X-Trace": "sync"}
    assert mock.sent_requests[1]["kwargs"] == {"timeout": 2.0}
    update_record = mock.sent_requests[3]
    assert update_record["method"] == "PUT"
    assert type(update_record["data"]) is dict
    assert update_record["data"] == {"IsExcludedFromCampaigns": True}
    assert update_record["headers"] == {"X-Update": "1"}
    assert update_record["kwargs"] == {"extra_flag": "yes"}
    assert mock.sent_requests[5]["method"] == "GET"
    assert mock.sent_requests[5]["filters"] == {"Limit": 5}


def test_mock_mailjet_client_sync_errors_streaming_ping_and_validation() -> None:
    """Exercise sync MockMailjetClient error status mapping, stream iterators, ping operators, and ID guards."""
    # Status >= 400 records Status="error" and raise_for_status maps SDK errors
    with MockMailjetClient(default_status=400) as bad_req:
        resp_400 = bad_req.contact.create(data={"Email": "bad"})
        assert resp_400.json()["Status"] == "error"
        with pytest.raises(ValidationError):
            resp_400.raise_for_status()

    with MockMailjetClient(default_status=429) as rate_limited:
        resp_429 = rate_limited.contact.get()
        with pytest.raises(ApiRateLimitError):
            resp_429.raise_for_status()

    with MockMailjetClient(default_status=500) as server_err:
        resp_500 = server_err.contact.get()
        with pytest.raises(MailjetApiError):
            resp_500.raise_for_status()

    # Invalid ID checks for delete()
    with MockMailjetClient() as mock:
        for invalid_id in ("", "   ", None, True, False):
            with pytest.raises(ValueError, match="non-empty, non-boolean resource 'id'"):
                mock.contact.delete(id=invalid_id)  # type: ignore[arg-type]

        # validate_stream_args rejections
        with pytest.raises(ValueError, match="chunk_size"):
            mock.contact.stream(chunk_size=0)
        with pytest.raises(ValueError, match="chunk_size"):
            mock.contact.stream(chunk_size=1001)
        with pytest.raises(ValueError, match="GET requests only"):
            mock.contact.stream(method="POST")

    # Direct _MockStreamIterator sync iteration over non-empty items
    sync_iter = _MockStreamIterator(({"ID": 1}, {"ID": 2}))
    assert list(sync_iter) == [{"ID": 1}, {"ID": 2}]

    # _MockPingResult equality, bool, hash, repr across 200 vs 503
    with MockMailjetClient(default_status=200) as ok_client, MockMailjetClient(default_status=503) as fail_client:
        ping_ok = ok_client.ping(timeout=1.5)
        ping_fail = fail_client.ping()

        assert isinstance(ping_ok, _MockPingResult)
        assert bool(ping_ok) is True
        assert bool(ping_fail) is False
        assert ping_ok == True
        assert ping_ok != False
        assert ping_fail == False
        assert ping_ok == _MockPingResult(True)
        assert ping_ok != _MockPingResult(False)
        assert ping_ok.__eq__("other") is NotImplemented
        assert ping_ok != "other"
        assert hash(ping_ok) == hash(True)
        assert hash(ping_fail) == hash(False)
        assert repr(ping_ok) == "True"
        assert repr(ping_fail) == "False"
