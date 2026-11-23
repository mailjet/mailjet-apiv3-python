"""Unit tests for mailjet_rest.webhooks HMAC-SHA256 verification and replay protection."""

from __future__ import annotations

import hashlib
import hmac
import time
from unittest.mock import patch

import pytest

from mailjet_rest.webhooks import verify_webhook_signature


def test_verify_webhook_signature_valid_replay_and_edge_cases() -> None:
    """verify_webhook_signature enforces constant-time HMAC-SHA256 digests and replay windows."""
    secret = "whsec_test_secret_123"  # pragma: allowlist secret
    payload = b'{"event":"sent","MessageID":42}'
    digest = hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()

    now_ts = int(time.time())
    assert verify_webhook_signature(payload, digest, secret) is True
    assert verify_webhook_signature(payload, f"  SHA256={digest.upper()}  ", secret, timestamp_unix=now_ts) is True
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts - 299, max_age_seconds=300) is True

    # Tampered payload, secret, or signature fails closed
    assert verify_webhook_signature(b'{"event":"open"}', digest, secret) is False
    assert verify_webhook_signature(payload, digest, "wrong_secret") is False  # pragma: allowlist secret
    assert verify_webhook_signature(payload, "0" * 64, secret) is False
    assert verify_webhook_signature(payload, "", secret) is False

    # Replay window rejection (both old past timestamps and far-future clock skew)
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts - 301, max_age_seconds=300) is False
    assert verify_webhook_signature(payload, digest, secret, timestamp_unix=now_ts + 301, max_age_seconds=300) is False

    # Non-ASCII signature headers and lone UTF-16 surrogates fail closed without raising
    assert verify_webhook_signature(payload, "ключ_не_ascii", secret) is False
    assert verify_webhook_signature(payload, "\ud800", secret) is False
    assert verify_webhook_signature(payload, digest, "bad_\ud800_secret") is False  # pragma: allowlist secret

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


def _sign_hex(secret: str, payload: bytes) -> str:
    return hmac.new(secret.encode("utf-8"), payload, hashlib.sha256).hexdigest()


def test_webhooks_exact_boundaries_defaults_and_error_messages() -> None:
    """Kill surviving mutants in mailjet_rest.webhooks.verify_webhook_signature."""
    payload = b'{"event":"open"}'
    secret = "whsec_mut_test"  # pragma: allowlist secret
    sig = _sign_hex(secret, payload)

    with patch("mailjet_rest.webhooks.time.time", return_value=1000.0):
        # Default max_age_seconds=300: delta == 300 passes, delta == 301 fails
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=700) is True
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=699) is False
        # max_age_seconds=0: delta == 0 passes, delta == 1 fails
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=1000, max_age_seconds=0) is True
        assert verify_webhook_signature(payload, sig, secret, timestamp_unix=999, max_age_seconds=0) is False

    with pytest.raises(TypeError) as e_payload:
        verify_webhook_signature("not-bytes", sig, secret)  # type: ignore[arg-type]
    assert str(e_payload.value) == "payload_bytes must be bytes, got str."

    with pytest.raises(TypeError) as e_sig:
        verify_webhook_signature(payload, 123, secret)  # type: ignore[arg-type]
    assert str(e_sig.value) == "signature_header must be str, got int."

    with pytest.raises(TypeError) as e_secret:
        verify_webhook_signature(payload, sig, 123)  # type: ignore[arg-type]
    assert str(e_secret.value) == "webhook_secret must be str, got int."

    with pytest.raises(ValueError) as e_age:
        verify_webhook_signature(payload, sig, secret, max_age_seconds=-1)
    assert str(e_age.value) == "max_age_seconds must be a non-negative integer."

    with pytest.raises(TypeError) as e_ts:
        verify_webhook_signature(payload, sig, secret, timestamp_unix="1000")  # type: ignore[arg-type]
    assert str(e_ts.value) == "timestamp_unix must be int or None, got str."


def test_verify_webhook_signature_empty_whitespace_secret_and_replay_arg_guards() -> None:
    """Validate empty/whitespace webhook_secret and replay-argument TypeError/ValueError branches."""
    payload = b'{"event":"bounce"}'
    secret = "whsec_guard_test"  # pragma: allowlist secret
    sig = _sign_hex(secret, payload)

    for bad_secret in ("", "   \t\n  "):  # pragma: allowlist secret
        with pytest.raises(ValueError, match=r"^webhook_secret must be a non-empty string\.$"):
            verify_webhook_signature(payload, sig, bad_secret)

    with pytest.raises(TypeError, match=r"^signed_timestamp must be bool, got int\.$"):
        verify_webhook_signature(payload, sig, secret, signed_timestamp=1)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"^signed_timestamp must be bool, got str\.$"):
        verify_webhook_signature(payload, sig, secret, signed_timestamp="true")  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"^timestamp_unix is required when signed_timestamp=True\.$"):
        verify_webhook_signature(payload, sig, secret, signed_timestamp=True)

    with pytest.raises(ValueError, match=r"^max_age_seconds must be a non-negative integer\.$"):
        verify_webhook_signature(payload, sig, secret, max_age_seconds=False)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=r"^max_age_seconds must be a non-negative integer\.$"):
        verify_webhook_signature(payload, sig, secret, max_age_seconds="300")  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"^timestamp_unix must be int or None, got bool\.$"):
        verify_webhook_signature(payload, sig, secret, timestamp_unix=False)  # type: ignore[arg-type]

    with pytest.raises(TypeError, match=r"^timestamp_unix must be int or None, got float\.$"):
        verify_webhook_signature(payload, sig, secret, timestamp_unix=12.5)  # type: ignore[arg-type]


def test_verify_webhook_signature_signed_timestamp_and_encoding_boundaries() -> None:
    """Cover signed_timestamp=True MAC formatting, zero-age future skew, empty payload, and UTF-8 secrets."""
    payload = b'{"event":"click","MessageID":77}'
    secret = "whsec_signed_ts_test_ключ"  # pragma: allowlist secret
    ts = 1000
    signed_input = f"{ts}.".encode("ascii") + payload
    ts_sig = _sign_hex(secret, signed_input)
    raw_sig = _sign_hex(secret, payload)

    with patch("mailjet_rest.webhooks.time.time", return_value=1000.0):
        assert verify_webhook_signature(payload, ts_sig, secret, timestamp_unix=ts, signed_timestamp=True) is True
        assert (
            verify_webhook_signature(
                payload,
                f" sha256={ts_sig.upper()} ",
                secret,
                timestamp_unix=ts,
                signed_timestamp=True,
            )
            is True
        )
        # Raw payload MAC without timestamp prefix must fail when signed_timestamp=True
        assert verify_webhook_signature(payload, raw_sig, secret, timestamp_unix=ts, signed_timestamp=True) is False
        # Mismatched timestamp within replay window must fail HMAC check
        assert verify_webhook_signature(payload, ts_sig, secret, timestamp_unix=ts + 1, signed_timestamp=True) is False
        # max_age_seconds=0 rejects both future (+1) and past (-1) clock skew
        assert (
            verify_webhook_signature(
                payload,
                ts_sig,
                secret,
                timestamp_unix=ts + 1,
                max_age_seconds=0,
                signed_timestamp=True,
            )
            is False
        )
        assert (
            verify_webhook_signature(
                payload,
                ts_sig,
                secret,
                timestamp_unix=ts - 1,
                max_age_seconds=0,
                signed_timestamp=True,
            )
            is False
        )
        # Replay window expired before HMAC computation
        assert (
            verify_webhook_signature(
                payload,
                ts_sig,
                secret,
                timestamp_unix=600,
                max_age_seconds=300,
                signed_timestamp=True,
            )
            is False
        )

    # Empty payload bytes verify cleanly when signed properly
    empty_sig = _sign_hex(secret, b"")
    assert verify_webhook_signature(b"", empty_sig, secret) is True
    # Lone UTF-16 surrogates fail closed even after prefix stripping
    assert verify_webhook_signature(payload, "sha256=\udfff", secret) is False
    assert verify_webhook_signature(payload, raw_sig, "sec_\udcff") is False  # pragma: allowlist secret
