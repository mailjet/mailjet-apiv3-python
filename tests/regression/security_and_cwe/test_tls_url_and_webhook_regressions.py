"""Regression tests for TLS CA verification paths, target URL validation, and webhook signatures."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
import time

import pytest

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.transport_security import resolve_tls_verify
from mailjet_rest.webhooks import verify_webhook_signature


@pytest.mark.parametrize(
    "bad_verify_path",
    [
        "~nonexistent_mailjet_user_99999/ca-bundle.pem",
        "~",
    ],
)
def test_resolve_tls_verify_unresolvable_tilde_raises_value_error(
    bad_verify_path: str,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Ensure Path.expanduser() RuntimeError is converted into ValueError."""
    if bad_verify_path == "~":
        monkeypatch.delenv("HOME", raising=False)
        monkeypatch.delenv("USERPROFILE", raising=False)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        Config(verify=bad_verify_path)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        SecurityGuard.resolve_tls_verify(bad_verify_path)

    with pytest.raises(ValueError, match="Invalid CA bundle path|Custom CA bundle path"):
        resolve_tls_verify(bad_verify_path)


def test_fuzz_config_tilde_crash_replay() -> None:
    """Replay any saved Atheris crash units if present in the repository root."""
    crash_files = sorted(Path().glob("crash-*"))
    if not crash_files:
        pytest.skip("No crash artifacts present on disk.")

    atheris = pytest.importorskip("atheris")
    from tests.fuzz.clients.fuzz_config import TestOneInput

    for crash_file in crash_files:
        TestOneInput(crash_file.read_bytes())
    assert atheris is not None


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


@pytest.mark.parametrize(
    "cleartext_remote_url",
    [
        "http://mailjet.com",
        "http://api.mailjet.com",
        "http://api.mailjet.com/",
        "http://api.us.mailjet.com/v3.1/send",
        "http://API.MAILJET.COM/v3/REST/contact",
    ],
)
def test_http_scheme_rejected_for_mailjet_domains_cwe319(cleartext_remote_url: str) -> None:
    """CWE-319: Unencrypted 'http://' must be rejected for mailjet.com and *.mailjet.com."""
    with pytest.raises(ValueError, match="CWE-319") as exc_cfg:
        Config(api_url=cleartext_remote_url)
    assert "CWE-319" in str(exc_cfg.value)
    with pytest.raises(ValueError, match="CWE-319"):
        SecurityGuard.validate_target_url(cleartext_remote_url, base_api_url="https://api.mailjet.com/")
    with Client(auth=("pub", "priv")) as client, pytest.raises(ValueError, match="CWE-319"):
        client.api_call(auth=("pub", "priv"), method="GET", url=cleartext_remote_url)


@pytest.mark.parametrize(
    "loopback_url",
    [
        "http://localhost:8080/",
        "http://127.0.0.1:8080/",
        "http://[::1]:8080/",
        "https://localhost:8443/",
        "https://127.0.0.1:8443/",
        "https://[::1]:8443/",
    ],
)
def test_http_and_https_allowed_for_loopback_hosts(loopback_url: str) -> None:
    """Loopback hosts ('localhost', '127.0.0.1', '::1') remain permitted over both http and https."""
    cfg = Config(api_url=loopback_url)
    assert cfg.api_url == loopback_url
    SecurityGuard.validate_target_url(f"{loopback_url}v3/REST/contact", base_api_url=loopback_url)
