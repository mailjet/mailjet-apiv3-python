"""Webhook HMAC-SHA256 verification helpers with replay-window enforcement."""

from __future__ import annotations

import hashlib
import hmac
import time


__all__ = ["verify_webhook_signature"]


def _validate_webhook_strings(
    payload_bytes: bytes,
    signature_header: str,
    webhook_secret: str,
) -> None:
    if not isinstance(payload_bytes, bytes):
        msg = f"payload_bytes must be bytes, got {type(payload_bytes).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if not isinstance(signature_header, str):
        msg = f"signature_header must be str, got {type(signature_header).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if not isinstance(webhook_secret, str):
        msg = f"webhook_secret must be str, got {type(webhook_secret).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if not webhook_secret or not webhook_secret.strip():
        msg = "webhook_secret must be a non-empty string."
        raise ValueError(msg)


def _validate_non_bool_int_bounds(value: object, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        msg = f"{name} must be a non-negative integer."
        raise ValueError(msg)


def _validate_webhook_replay_args(
    timestamp_unix: int | None,
    max_age_seconds: int,
    signed_timestamp: bool,
) -> None:
    if not isinstance(signed_timestamp, bool):
        msg = f"signed_timestamp must be bool, got {type(signed_timestamp).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    _validate_non_bool_int_bounds(max_age_seconds, "max_age_seconds")
    if timestamp_unix is not None and (isinstance(timestamp_unix, bool) or not isinstance(timestamp_unix, int)):
        msg = f"timestamp_unix must be int or None, got {type(timestamp_unix).__name__}."
        raise TypeError(msg)
    if signed_timestamp and timestamp_unix is None:
        msg = "timestamp_unix is required when signed_timestamp=True."
        raise ValueError(msg)


def _validate_webhook_inputs(
    payload_bytes: bytes,
    signature_header: str,
    webhook_secret: str,
    timestamp_unix: int | None,
    max_age_seconds: int,
    signed_timestamp: bool,
) -> None:
    _validate_webhook_strings(payload_bytes, signature_header, webhook_secret)
    _validate_webhook_replay_args(timestamp_unix, max_age_seconds, signed_timestamp)


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    webhook_secret: str,
    *,
    timestamp_unix: int | None = None,
    max_age_seconds: int = 300,
    signed_timestamp: bool = False,
) -> bool:
    """Verify HMAC-SHA256 webhook digest via constant-time ``hmac.compare_digest``.

    Warning:
        When ``signed_timestamp=False`` (raw payload MAC), ``timestamp_unix`` is NOT covered
        by the HMAC digest. Callers MUST parse ``timestamp_unix`` from inside the authenticated
        ``payload_bytes`` JSON (e.g. Mailjet's ``"time"`` field) rather than an unauthenticated
        HTTP header, or pass ``signed_timestamp=True`` when signing ``f"{timestamp_unix}." + payload``.

    Returns:
        bool: True when the digest matches (and ``timestamp_unix`` is within ``max_age_seconds``).
    """
    _validate_webhook_inputs(
        payload_bytes,
        signature_header,
        webhook_secret,
        timestamp_unix,
        max_age_seconds,
        signed_timestamp,
    )

    if timestamp_unix is not None and abs(int(time.time()) - timestamp_unix) > max_age_seconds:
        return False

    mac_input = f"{timestamp_unix}.".encode("ascii") + payload_bytes if signed_timestamp else payload_bytes
    normalized_sig = signature_header.strip().lower().removeprefix("sha256=")
    try:
        secret_bytes = webhook_secret.encode("utf-8")
        sig_bytes = normalized_sig.encode("utf-8")
    except UnicodeEncodeError:
        return False

    expected_bytes = hmac.new(secret_bytes, mac_input, hashlib.sha256).hexdigest().encode("ascii")
    return hmac.compare_digest(expected_bytes, sig_bytes)
