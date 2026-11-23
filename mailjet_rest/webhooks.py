"""Webhook HMAC-SHA256 verification helpers with replay-window enforcement."""

from __future__ import annotations

import hashlib
import hmac
import time


__all__ = ["verify_webhook_signature"]


def verify_webhook_signature(
    payload_bytes: bytes,
    signature_header: str,
    webhook_secret: str,
    *,
    timestamp_unix: int | None = None,
    max_age_seconds: int = 300,
) -> bool:
    """Verify HMAC-SHA256 webhook digest via constant-time ``hmac.compare_digest``.

    Returns:
        bool: True when the digest matches (and ``timestamp_unix`` is within ``max_age_seconds``).
    """
    if not isinstance(payload_bytes, bytes):
        msg = f"payload_bytes must be bytes, got {type(payload_bytes).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if not isinstance(signature_header, str):
        msg = f"signature_header must be str, got {type(signature_header).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if not isinstance(webhook_secret, str):
        msg = f"webhook_secret must be str, got {type(webhook_secret).__name__}."  # type: ignore[unreachable]
        raise TypeError(msg)
    if isinstance(max_age_seconds, bool) or not isinstance(max_age_seconds, int) or max_age_seconds < 0:
        msg = "max_age_seconds must be a non-negative integer."
        raise ValueError(msg)

    if timestamp_unix is not None:
        if isinstance(timestamp_unix, bool) or not isinstance(timestamp_unix, int):
            msg = f"timestamp_unix must be int or None, got {type(timestamp_unix).__name__}."
            raise TypeError(msg)
        if abs(int(time.time()) - timestamp_unix) > max_age_seconds:
            return False

    normalized_sig = signature_header.strip().lower().removeprefix("sha256=")
    try:
        secret_bytes = webhook_secret.encode("utf-8")
        sig_bytes = normalized_sig.encode("utf-8")
    except UnicodeEncodeError:
        return False

    expected_bytes = hmac.new(secret_bytes, payload_bytes, hashlib.sha256).hexdigest().encode("ascii")
    return hmac.compare_digest(expected_bytes, sig_bytes)
