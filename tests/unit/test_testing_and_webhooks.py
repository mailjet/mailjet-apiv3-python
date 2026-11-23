"""Unit tests for MOD-03 Ecosystem DX modules (mailjet_rest.testing and mailjet_rest.webhooks)."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import subprocess
import sys
import time
from typing import Any

import pytest

from mailjet_rest import MockMailjetClient as LazyMockMailjetClient, verify_webhook_signature as lazy_verify
from mailjet_rest.errors import DoesNotExistError, MailjetApiError, ValidationError
from mailjet_rest.testing import MockEndpoint, MockMailjetClient, MockResponse
from mailjet_rest.webhooks import verify_webhook_signature


def test_top_level_lazy_exports_and_cold_boot_isolation() -> None:
    """MOD-03 helpers are lazily re-exported from mailjet_rest without eager import overhead."""
    assert LazyMockMailjetClient is MockMailjetClient
    assert lazy_verify is verify_webhook_signature

    code = (
        "import json, sys, mailjet_rest; "
        "loaded = [m for m in ('mailjet_rest.testing', 'mailjet_rest.webhooks', 'dataclasses') if m in sys.modules]; "
        "exported = dir(mailjet_rest); "
        "sys.stdout.write(json.dumps({'loaded': loaded, "
        "'has_mock': 'MockMailjetClient' in exported, "
        "'has_verify': 'verify_webhook_signature' in exported}))"
    )
    proc = subprocess.run(
        [sys.executable, "-c", code],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    payload = json.loads(proc.stdout)
    assert payload["loaded"] == []
    assert payload["has_mock"] is True
    assert payload["has_verify"] is True


def test_mock_mailjet_client_direct_create_and_slots() -> None:
    """MockMailjetClient supports direct create(data=...), custom status, and slotted layout."""
    client = MockMailjetClient()
    assert not hasattr(client, "__dict__")

    payload: dict[str, Any] = {"Messages": [{"Subject": "Direct MOD-03 test"}]}
    res = client.create(data=payload)
    assert res == {"Status": "success", "StatusCode": 200}
    assert client.sent_requests == [{"data": payload}]

    custom = MockMailjetClient(default_status=202)
    assert custom.create(data={"ping": True}) == {"Status": "success", "StatusCode": 202}


def test_mock_mailjet_client_endpoints_and_context_managers() -> None:
    """MockMailjetClient records endpoint CRUD calls, sync/async context managers, and HTTP errors."""
    with MockMailjetClient() as mock_client:
        endpoint = mock_client.send_v31
        assert isinstance(endpoint, MockEndpoint)
        assert not hasattr(endpoint, "__dict__")

        create_resp = endpoint.create(data={"Messages": [{"Subject": "Hi"}]}, headers={"X-Test": "1"})
        assert isinstance(create_resp, MockResponse)
        assert not hasattr(create_resp, "__dict__")
        assert create_resp.status_code == 200
        assert create_resp.json()["Status"] == "success"
        create_resp.raise_for_status()

        mock_client.contact.get(id=42, filters={"Limit": 5})
        mock_client.contact.update(id=42, data={"Name": "Updated"})
        mock_client.contact.patch(id=42, data={"Name": "Patched"})
        mock_client.contact.delete(id=42)
        mock_client.contact("GET", id=42, custom_flag=True)

        with pytest.raises(AttributeError, match="no attribute '_secret'"):
            _ = mock_client._secret  # ruff: ignore[private-member-access]

    assert [req["method"] for req in mock_client.sent_requests] == ["POST", "GET", "PUT", "PATCH", "DELETE", "GET"]
    assert mock_client.sent_requests[0]["endpoint"] == "send_v31"
    assert mock_client.sent_requests[0]["headers"] == {"X-Test": "1"}
    assert mock_client.sent_requests[1]["filters"] == {"Limit": 5}
    assert mock_client.sent_requests[-1]["kwargs"] == {"custom_flag": True}

    async def _async_ctx() -> None:
        async with MockMailjetClient(default_status=404) as aclient:
            resp = aclient.contact.get(id=999)
            assert resp.status_code == 404
            with pytest.raises(DoesNotExistError):
                resp.raise_for_status()

    asyncio.run(_async_ctx())

    with pytest.raises(ValidationError):
        MockResponse(status_code=400, text="bad payload").raise_for_status()
    with pytest.raises(MailjetApiError):
        MockResponse(status_code=503, text="unavailable").raise_for_status()


def test_verify_webhook_signature_valid_replay_and_edge_cases() -> None:
    """verify_webhook_signature enforces constant-time HMAC-SHA256 digests and replay windows."""
    secret = "whsec_test_secret_123"
    payload = b'{"event":"sent","MessageID":42}'
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    now_ts = int(time.time())
    assert verify_webhook_signature(payload, digest, secret) is True
    assert verify_webhook_signature(payload, f"  SHA256={digest.upper()}  ", secret, timestamp_unix=now_ts) is True
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts - 299, max_age_seconds=300) is True

    # Tampered payload, secret, or signature fails closed
    assert verify_webhook_signature(b'{"event":"open"}', digest, secret) is False
    assert verify_webhook_signature(payload, digest, "wrong_secret") is False
    assert verify_webhook_signature(payload, "0" * 64, secret) is False
    assert verify_webhook_signature(payload, "", secret) is False

    # Replay window rejection (both old past timestamps and far-future clock skew)
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts - 301, max_age_seconds=300) is False
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts + 301, max_age_seconds=300) is False

    # Non-ASCII signature headers and lone UTF-16 surrogates fail closed without raising
    assert verify_webhook_signature(payload, "ключ_не_ascii", secret) is False
    assert verify_webhook_signature(payload, "\ud800", secret) is False
    assert verify_webhook_signature(payload, digest, "bad_\ud800_secret") is False

    # Boundary argument validation
    with pytest.raises(TypeError, match="payload_bytes must be bytes"):
        verify_webhook_signature("not-bytes", digest, secret)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="signature_header must be str"):
        verify_webhook_signature(payload, 123, secret)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="webhook_secret must be str"):
        verify_webhook_signature(payload, digest, 456)  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="max_age_seconds must be a non-negative integer"):
        verify_webhook_signature(payload, digest, secret, max_age_seconds=-1)
    with pytest.raises(ValueError, match="max_age_seconds must be a non-negative integer"):
        verify_webhook_signature(payload, digest, secret, max_age_seconds=True)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="timestamp_unix must be int or None"):
        verify_webhook_signature(payload, digest, secret, timestamp_unix=True)  # type: ignore[arg-type]
