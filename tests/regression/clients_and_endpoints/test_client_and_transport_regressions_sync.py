"""Synchronous client, configuration, retry stream-rewind, and HTTP error regression tests."""

from __future__ import annotations

import builtins
import io
import json
from pathlib import Path
import types
from typing import Any

import pytest
import responses

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.errors import (
    MailjetApiError,
    MailjetNetworkError,
    TimeoutError as MailjetTimeoutError,
    raise_mapped_http_error,
)
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.retry import reset_stream_pointers, snapshot_stream_offsets


@pytest.mark.parametrize(
    ("header_name", "header_value", "payload"),
    [
        ("content-type", "application/json; charset=utf-8", {"Name": "Lowercase Header"}),
        ("CONTENT-TYPE", "Application/JSON", {"Name": "Uppercase Mixed Value"}),
        ("Content-Type", "application/problem+json; charset=utf-8", [{"Name": "List PlusJson"}]),
    ],
)
def test_sync_client_case_insensitive_json_content_type_serializes_json_body(
    header_name: str,
    header_value: str,
    payload: Any,
) -> None:
    """PR #179 #1: Sync Client must serialize Mapping/list bodies as JSON for any Content-Type casing/+json."""
    captured_bodies: list[bytes | str | None] = []

    with responses.RequestsMock() as rsps:

        def _callback(request: Any) -> tuple[int, dict[str, str], str]:
            captured_bodies.append(request.body)
            return 200, {"Content-Type": "application/json"}, '{"Count": 1, "Data": []}'

        rsps.add_callback(
            responses.POST,
            "https://api.mailjet.com/v3/REST/contact",
            callback=_callback,
        )
        with Client(auth=("pub", "priv")) as client:
            resp = client.contact.create(data=payload, headers={header_name: header_value})
            assert resp.status_code == 200

    assert len(captured_bodies) == 1
    raw_body = captured_bodies[0]
    assert raw_body is not None
    parsed = json.loads(raw_body.decode("utf-8") if isinstance(raw_body, bytes) else raw_body)
    assert parsed == payload


def test_sync_client_and_config_isolate_trust_env_by_default(
    monkeypatch: pytest.MonkeyPatch,
    tmp_path: Path,
) -> None:
    """PR #179 #3: Config.trust_env defaults to False, rejecting ambient HTTP_PROXY and .netrc unless opted in."""
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:9")
    monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:9")
    netrc_file = tmp_path / ".netrc"
    netrc_file.write_text("machine api.mailjet.com login netrc_user password netrc_secret\n", encoding="utf-8")
    monkeypatch.setenv("NETRC", str(netrc_file))

    default_cfg = Config()
    assert default_cfg.trust_env is False
    with pytest.raises(TypeError, match="trust_env must be a bool"):
        Config(trust_env="yes")  # type: ignore[arg-type]

    with Client(auth="bearer_tok_123") as sync_client:
        assert sync_client.session.trust_env is False
    with Client(auth="bearer_tok_123", trust_env=True) as opted_sync:
        assert opted_sync.session.trust_env is True


def test_sync_idempotency_key_scoped_by_method_url_and_sandbox_mode() -> None:
    """PR #179 #7: Idempotency-Key must differ across method, target URL, and SandboxMode."""
    fp_sandbox_true = SecurityGuard.generate_payload_fingerprint(
        {"Messages": [{"Subject": "Hi"}], "SandboxMode": True, "CustomID": "a", "EventPayload": "x"},
    )
    fp_sandbox_false = SecurityGuard.generate_payload_fingerprint(
        {"Messages": [{"Subject": "Hi"}], "SandboxMode": False, "CustomID": "b", "EventPayload": "y"},
    )
    assert fp_sandbox_true != fp_sandbox_false

    sync_keys: list[str] = []
    with responses.RequestsMock() as rsps:

        def _cb(request: Any) -> tuple[int, dict[str, str], str]:
            sync_keys.append(request.headers["Idempotency-Key"])
            return 200, {"Content-Type": "application/json"}, '{"Count": 1, "Data": []}'

        for method in (responses.PUT, responses.POST):
            rsps.add_callback(method, "https://api.mailjet.com/v3/REST/contact/1", callback=_cb)
        rsps.add_callback(responses.PUT, "https://api.mailjet.com/v3/REST/contact/2", callback=_cb)

        with Client(auth=("pub", "priv")) as sync_client:
            sync_client.contact.update(id=1, data={"IsExcludedFromCampaigns": True})
            sync_client.contact.update(id=2, data={"IsExcludedFromCampaigns": True})
            sync_client.contact.create(id=1, data={"IsExcludedFromCampaigns": True})

    assert len(sync_keys) == 3
    assert len(set(sync_keys)) == 3


def test_sync_stream_retry_preserves_nonzero_initial_seek_offset() -> None:
    """PR #179 #7: Stream rewind helpers and sync Client multipart uploads preserve nonzero initial seek offsets."""
    buf = io.BytesIO(b"SKIP_HEADER___REAL_BODY")
    buf.seek(14)
    files_payload: dict[str, Any] = {
        "attachment": ("slice.bin", buf, "application/octet-stream"),
    }
    offsets = snapshot_stream_offsets(None, files_payload)
    assert offsets == {id(buf): 14}
    assert buf.read() == b"REAL_BODY"

    reset_stream_pointers(None, files_payload, offsets)
    assert buf.tell() == 14

    captured_bodies: list[bytes] = []
    with responses.RequestsMock() as rsps:

        def _callback(request: Any) -> tuple[int, dict[str, str], str]:
            body = request.body
            captured_bodies.append(body if isinstance(body, bytes) else str(body).encode("utf-8"))
            return 200, {"Content-Type": "application/json"}, '{"OK": true}'

        rsps.add_callback(
            responses.POST,
            "https://api.mailjet.com/v3/REST/contact",
            callback=_callback,
        )
        with Client(auth=("pub", "priv")) as sync_client:
            resp = sync_client.contact.create(
                data={"Field": "val"},
                files=files_payload,
            )
            assert resp.status_code == 200

    assert len(captured_bodies) == 1
    assert b"REAL_BODY" in captured_bodies[0]
    assert b"SKIP_HEADER" not in captured_bodies[0]

    buf2 = io.BytesIO(b"PREFIX___TAIL")
    buf2.seek(9)
    reset_stream_pointers(buf2, None, {id(buf2): 9})
    assert buf2.tell() == 9


def test_raise_mapped_http_error_bounds_response_body() -> None:
    """PR #179 #9c: MailjetApiError.response_body must be bounded by MAX_ERROR_BODY_CHARS to prevent RAM bloat."""
    from mailjet_rest.errors import MAX_ERROR_BODY_CHARS

    huge_body = "X" * 50_000
    fake_resp = types.SimpleNamespace(
        status_code=502,
        text=huge_body,
        json=lambda: (_ for _ in ()).throw(ValueError("not json")),
    )
    with pytest.raises(MailjetApiError) as exc_info:
        raise_mapped_http_error(fake_resp, RuntimeError("upstream 502"))

    assert MAX_ERROR_BODY_CHARS == 16_384
    assert exc_info.value.response_body == f"{huge_body[:MAX_ERROR_BODY_CHARS]}...[truncated]"


def test_timeout_error_inherits_from_builtin_timeout_error() -> None:
    """PR #179 #12b: mailjet_rest.errors.TimeoutError must satisfy builtins.TimeoutError handlers (PEP 3151)."""
    assert issubclass(MailjetTimeoutError, builtins.TimeoutError)
    assert issubclass(MailjetTimeoutError, MailjetNetworkError)

    def _raise_timeout() -> None:
        raise MailjetTimeoutError("request timed out")

    with pytest.raises(builtins.TimeoutError, match="request timed out"):
        _raise_timeout()


def test_dry_run_sync_returns_valid_json_body() -> None:
    """PR #179 #12c: Synchronous dry_run=True mutations must return valid parseable JSON payloads."""
    expected = {"DryRun": True, "Count": 0, "Total": 0, "Data": [], "Messages": []}
    with Client(auth=("pub", "priv"), dry_run=True) as sync_client:
        sync_resp = sync_client.contact.create(data={"Email": "dryrun@example.com"})
        assert sync_resp.status_code == 200
        assert sync_resp.json() == expected
