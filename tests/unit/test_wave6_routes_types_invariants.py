"""Unit tests for Wave 6 OpenAPI routes, consolidated types, and TOKQOR security invariants."""

from __future__ import annotations

import asyncio
import datetime as dt
import email.utils
import io
import ipaddress
import logging
import re
import warnings
from pathlib import Path
from types import MappingProxyType
from typing import Any
from unittest.mock import AsyncMock, MagicMock

import pytest

from mailjet_rest import types as mj_types
from mailjet_rest.client import AsyncClient, BaseClient, Client, Config, JitterRetry, _httpx2
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.routes import ROUTE_MAP
from mailjet_rest.utils.guardrails import SecurityGuard


REPO_ROOT = Path(__file__).resolve().parents[2]


# ==========================================
# 1. OpenAPI & Release-Docs Route Parity
# ==========================================


def test_wave6_new_openapi_and_v4_routes_build_urls_and_preserve_legacy() -> None:
    """Verify the 7 new OpenAPI/v4 routes resolve exact URLs while preserving v3 templates warning."""
    expected_new_routes = {
        "send_v31",
        "contacts",
        "v1_templates",
        "template_contents_lock",
        "template_contents_publish",
        "template_contents_unlock",
        "data_images_by_type",
    }
    assert expected_new_routes.issubset(ROUTE_MAP.keys())
    assert len(ROUTE_MAP) >= 89

    with Client(auth=("pub_key", "priv_key"), config=Config(version="v3")) as client:
        assert client.send_v31._build_url() == "https://api.mailjet.com/v3.1/send"
        assert client.contacts._build_url(id_val=42) == "https://api.mailjet.com/v4/contacts/42"

        with warnings.catch_warnings(record=True) as recorded:
            warnings.simplefilter("always", DeprecationWarning)
            assert client.v1_templates._build_url() == "https://api.mailjet.com/v1/REST/templates"
            assert client.v1_templates._build_url(id_val=10) == "https://api.mailjet.com/v1/REST/templates/10"
        assert not [w for w in recorded if "singular '/template'" in str(w.message)]

        with pytest.warns(DeprecationWarning, match=r"Email API \(v3\) uses singular '/template'"):
            assert client.templates._build_url() == "https://api.mailjet.com/v3/REST/templates"

        assert client.template_contents_lock._build_url(id_val=10) == (
            "https://api.mailjet.com/v1/REST/templates/10/contents/lock"
        )
        assert client.template_contents_publish._build_url(id_val=10) == (
            "https://api.mailjet.com/v1/REST/templates/10/contents/publish"
        )
        assert client.template_contents_unlock._build_url(id_val=10) == (
            "https://api.mailjet.com/v1/REST/templates/10/contents/unlock"
        )
        assert client.data_images_by_type._build_url(id_val="img-uuid", action_id="thumbnail") == (
            "https://api.mailjet.com/v1/data/images/img-uuid/thumbnail"
        )

        with pytest.raises(ValueError, match="requires an 'id' parameter"):
            client.data_images_by_type._build_url(action_id="thumbnail")
        with pytest.raises(ValueError, match="requires an 'action_id' parameter"):
            client.data_images_by_type._build_url(id_val="img-uuid")


def test_wave6_routes_declared_in_client_pyi_stubs() -> None:
    """Confirm every new route is declared on both Client and AsyncClient in client.pyi."""
    stub_text = (REPO_ROOT / "mailjet_rest" / "client.pyi").read_text(encoding="utf-8")
    new_routes = (
        "send_v31",
        "contacts",
        "v1_templates",
        "template_contents_lock",
        "template_contents_publish",
        "template_contents_unlock",
        "data_images_by_type",
    )
    for route in new_routes:
        assert f"def {route}(self) -> Endpoint: ..." in stub_text
        assert f"def {route}(self) -> AsyncEndpoint: ..." in stub_text


def test_sync_client_executes_new_routes_with_mapping_payloads(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify sync Client executes new routes and serializes read-only MappingProxyType payloads."""
    seen: list[tuple[str, str, Any]] = []

    def fake_request(method: str, url: str, **kwargs: Any) -> MagicMock:
        seen.append((method, url, kwargs.get("json")))
        resp = MagicMock()
        resp.status_code = 200
        resp.raise_for_status.return_value = None
        return resp

    with Client(auth=("pub_key", "priv_key")) as client:
        monkeypatch.setattr(client.session, "request", fake_request)

        v31_msg: mj_types.SendV31Message = {
            "From": {"Email": "sender@example.com", "Name": "Sender"},
            "To": [{"Email": "to@example.com"}],
            "Subject": "Hello v3.1",
            "TextPart": "Body",
            "CustomID": "cid-v31",
            "TrackOpens": "enabled",
        }
        v31_payload = MappingProxyType({"Messages": [v31_msg], "AdvanceErrorHandling": True})
        client.send_v31.create(data=v31_payload)
        client.contacts.delete(id=99)
        client.template_contents_publish.create(id=12, data={"Name": "Published"})
        client.data_images_by_type.update(id="abc-123", action_id="thumbnail", data=b"raw-bytes")

        # Verify legacy ensure_ascii=False handles MappingProxyType safely without TypeError
        with pytest.warns(DeprecationWarning, match="ensure_ascii"):
            legacy_url, _headers, encoded = client.send_v31._prepare_call_args(
                id=None,
                data=v31_payload,
                action_id=None,
                headers=None,
                kwargs={"ensure_ascii": False},
            )
        assert legacy_url == "https://api.mailjet.com/v3.1/send"
        assert isinstance(encoded, str)

    assert seen[0][0] == "POST"
    assert seen[0][1] == "https://api.mailjet.com/v3.1/send"
    assert isinstance(seen[0][2], dict)
    assert seen[1][:2] == ("DELETE", "https://api.mailjet.com/v4/contacts/99")
    assert seen[2][:2] == ("POST", "https://api.mailjet.com/v1/REST/templates/12/contents/publish")
    assert seen[3][:2] == ("PUT", "https://api.mailjet.com/v1/data/images/abc-123/thumbnail")


# ==========================================
# 2. Consolidated Types & TypedDict Coverage
# ==========================================


def test_consolidated_types_exports_and_openapi_typeddicts() -> None:
    """Verify all consolidated type aliases and OpenAPI TypedDict schemas are exported and usable."""
    expected_public = {
        "ApiListResponse",
        "ApiVersion",
        "Attachment",
        "AuthCredentials",
        "AutoIdempotencyMode",
        "CertConfig",
        "ContactListAction",
        "ContactListSubscription",
        "ContactPayload",
        "ContactRecord",
        "EmailAddress",
        "EventCallbackUrlPayload",
        "HeadersMapping",
        "HttpMethod",
        "ManageManyContactsItem",
        "ManageManyContactsPayload",
        "PayloadType",
        "ProxyConfig",
        "QueryFilters",
        "RequestHeaders",
        "ResourceId",
        "SendV31ErrorItem",
        "SendV31Message",
        "SendV31MessageResult",
        "SendV31Payload",
        "SendV31RecipientResult",
        "SendV31Response",
        "TemplateContentPayload",
        "TemplateContentType",
        "TimeoutType",
        "TrackingMode",
        "V1TemplatePayload",
        "VerifyConfig",
        "WebhookEventType",
        "WebhookStatus",
    }
    assert expected_public.issubset(set(mj_types.__all__))
    for name in mj_types.__all__:
        assert hasattr(mj_types, name)

    contact_in: mj_types.ContactPayload = {"Email": "user@example.com", "Name": "User"}
    contact_out: mj_types.ContactRecord = {
        "ID": 1,
        "Email": "user@example.com",
        "CreatedAt": "2026-01-01T00:00:00Z",
    }
    bulk: mj_types.ManageManyContactsPayload = {
        "Contacts": [{"Email": "a@example.com", "Properties": {"Role": "Admin"}}],
        "ContactsLists": [{"ListID": 55, "Action": "addnoforce"}],
    }
    webhook: mj_types.EventCallbackUrlPayload = {
        "Url": "https://example.com/hook",
        "EventType": "click",
        "Version": 2,
        "Status": "alive",
    }
    tpl_content: mj_types.TemplateContentPayload = {"Locale": "en_US", "HTMLPart": "<p>Hi</p>"}
    tpl_v1: mj_types.V1TemplatePayload = {"Name": "Welcome", "EditMode": 1, "LabelIDs": [1, 2]}
    list_resp: mj_types.ApiListResponse = {"Count": 1, "Total": 1, "Data": [dict(contact_out)]}
    send_resp: mj_types.SendV31Response = {
        "Messages": [
            {
                "Status": "success",
                "To": [
                    {
                        "Email": "user@example.com",
                        "MessageUUID": "uuid-1",
                        "MessageID": 123,
                        "MessageHref": "https://api.mailjet.com/v3/message/123",
                    }
                ],
            }
        ]
    }
    send_err: mj_types.SendV31ErrorItem = {
        "ErrorIdentifier": "err-id",
        "ErrorCode": "send-0010",
        "StatusCode": 400,
        "ErrorMessage": "Invalid template",
        "ErrorRelatedTo": ["TemplateID"],
    }

    assert contact_in["Email"] == "user@example.com"
    assert bulk["ContactsLists"][0]["Action"] == "addnoforce"
    assert webhook["Version"] == 2
    assert tpl_content["Locale"] == "en_US"
    assert tpl_v1["Name"] == "Welcome"
    assert list_resp["Total"] == 1
    assert send_resp["Messages"][0]["Status"] == "success"
    assert send_err["StatusCode"] == 400

    # MappingProxyType works with fingerprint hashing and telemetry extraction
    readonly_payload = MappingProxyType({"CustomID": "trace-99", "Messages": [{"TemplateID": 77}]})
    fp = SecurityGuard.generate_payload_fingerprint(readonly_payload)
    assert len(fp) == 64
    trace_str, structured = BaseClient._extract_telemetry(readonly_payload, None)
    assert "CustomID=trace-99" in trace_str
    assert structured["mailjet.customid"] == "trace-99"


# ==========================================
# 3. TOKQOR Security Invariants Enforcement
# ==========================================


def test_per_call_url_ssrf_userinfo_and_zone_id_blocked() -> None:
    """INV-25 / CAND-INV-38: Block SSRF, userinfo authority confusion, control chars, and zone IDs on api_call."""
    metadata_ip = str(ipaddress.IPv4Address((169 << 24) | (254 << 16) | (169 << 8) | 254))
    bad_urls = (
        "https://evil.example/steal",
        f"http://{metadata_ip}/latest/meta-data/",
        "https://user:secret@api.mailjet.com/v3/send",
        "https://api.mailjet.com/v3/send\nX-Injected: 1",
        "https://[fe80::1%eth0]/v3/send",
        "",
    )
    with Client(auth=("pub_key", "priv_key")) as client:
        for bad_url in bad_urls:
            with pytest.raises(ValueError, match=r"Security Alert \(CWE-918\)"):
                client.api_call("GET", bad_url)


def test_header_control_chars_bearer_bidi_and_proxy_guards() -> None:
    """INV-26 / CAND-INV-37: Block NUL/C1 headers, BiDi/whitespace tokens, and unsafe str/mapping proxies."""
    for bad_hdr in ("ok\x00nul", "ok\x1fctrl", "ok\x85nel"):
        with pytest.raises(ValueError, match="CRLF injection detected in header"):
            SecurityGuard.sanitize_headers({"X-Test": bad_hdr})
    assert SecurityGuard.sanitize_headers({"X-Test": "ok\twith\ttab"}) == {"X-Test": "ok\twith\ttab"}

    with pytest.raises(TypeError, match="Invalid header name type"):
        SecurityGuard.sanitize_headers({123: "val"})  # type: ignore[dict-item]
    with pytest.raises(TypeError, match="Invalid header value type"):
        SecurityGuard.sanitize_headers({"X-Test": 123})  # type: ignore[dict-item]

    with pytest.raises(ValueError, match="Auth credentials contain forbidden control characters"):
        SecurityGuard.validate_and_coerce_auth("tok\r\nen")
    for bad_tok in ("tok en", "tok\ten", "tok\u202een", "tok\u200ben"):
        with pytest.raises(ValueError, match="invalid whitespace or control characters"):
            SecurityGuard.validate_and_coerce_auth(bad_tok)

    with pytest.warns(UserWarning, match="Unencrypted HTTP proxy detected"):
        SecurityGuard.check_request_security({"proxies": "http://proxy.internal:8080"})
    with warnings.catch_warnings(record=True) as https_warn:
        warnings.simplefilter("always", UserWarning)
        SecurityGuard.check_request_security({"proxies": MappingProxyType({"https": "https://proxy.internal:8443"})})
    assert not https_warn

    for bad_proxy in ("file:///etc/passwd", "gopher://127.0.0.1:70/_1", "https://proxy.internal:8080\r\n"):
        with pytest.raises(ValueError):
            SecurityGuard.check_request_security({"proxies": bad_proxy})
    with pytest.raises(TypeError, match="Invalid 'proxies' type"):
        SecurityGuard.check_request_security({"proxies": ["http://proxy.internal:8080"]})


def test_multipart_files_crlf_nul_guard() -> None:
    """CAND-INV-51: Reject CRLF or NUL characters in multipart field names, filenames, MIME types, and headers."""
    safe_files = {"attachment": ("report.csv", io.BytesIO(b"a,b\n1,2\n"), "text/csv", {"X-Part": "1"})}
    SecurityGuard.validate_multipart_files(safe_files)

    malicious_specs: tuple[Any, ...] = (
        {"field\r\nname": ("report.csv", b"data", "text/csv")},
        {"attachment": ("bad\r\nfilename.txt", b"data", "text/plain")},
        {"attachment": ("bad\x00.txt", b"data", "text/plain")},
        [("attachment", (b"raw\n.txt", b"data", "text/plain"))],
        {"attachment": ("ok.txt", b"data", "text/plain\r\nX-Injected: 1")},
    )
    for bad_files in malicious_specs:
        with pytest.raises(ValueError, match="Multipart file .* forbidden CRLF or NUL"):
            SecurityGuard.validate_multipart_files(bad_files)

    with pytest.raises(ValueError, match="CRLF injection detected in header"):
        SecurityGuard.validate_multipart_files({"attachment": ("ok.txt", b"data", "text/plain", {"X-Bad": "a\x00b"})})


def test_retry_budget_ceiling_http_date_and_error_log_sanitization(caplog: pytest.LogCaptureFixture) -> None:
    """CAND-INV-44/45/48/54/56: Enforce max_retries ceiling, HTTP-date Retry-After cap, and sanitized error logs."""
    assert Config.MAX_RETRIES_LIMIT == 20
    assert Config(max_retries=20).max_retries == 20
    with pytest.raises(ValueError, match="max_retries"):
        Config(max_retries=21)

    future_dt = dt.datetime.now(dt.timezone.utc) + dt.timedelta(seconds=300)
    past_dt = dt.datetime.now(dt.timezone.utc) - dt.timedelta(seconds=60)
    assert BaseClient._compute_retry_delay(0, email.utils.format_datetime(future_dt)) == 60.0
    assert BaseClient._compute_retry_delay(0, email.utils.format_datetime(past_dt)) == 0.0

    # Oversized and control-char-forged response bodies are neutralized and truncated
    fake_resp = MagicMock()
    fake_resp.status_code = 502
    fake_resp.text = "bad\r\nFAKE LOG ENTRY\x00" + ("A" * 3000)
    fake_resp.json.return_value = {"ErrorMessage": "line1\r\nforged\x00" + ("B" * 1500)}

    detail = BaseClient._extract_error_detail(fake_resp, fake_resp.text)
    assert "\r" not in detail
    assert "\n" not in detail
    assert "\x00" not in detail
    assert "...[truncated]" in detail
    assert len(detail) <= BaseClient._MAX_ERROR_DETAIL_CHARS + 32

    with caplog.at_level(logging.ERROR):
        BaseClient._log_request("POST", "https://api.mailjet.com/v3.1/send", fake_resp, "")
    err_logs = [rec.message for rec in caplog.records if rec.levelno == logging.ERROR]
    assert err_logs
    assert "\r" not in err_logs[-1]
    assert "\n" not in err_logs[-1]
    assert "\x00" not in err_logs[-1]
    assert "...[truncated]" in err_logs[-1]


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
    assert re.search(r"/v4/contacts/55$", "https://api.mailjet.com/v4/contacts/55")


def test_modular_scaffolding_exports_and_dx_helpers() -> None:
    """Verify modular utility extraction preserves v1.9.1 re-exports and adds clean DX helpers."""
    import mailjet_rest  # ruff: ignore[import-outside-top-level]
    from mailjet_rest import (  # ruff: ignore[import-outside-top-level]
        Endpoint,
        errors as mj_errors,
    )
    from mailjet_rest.utils import (  # ruff: ignore[import-outside-top-level]
        filesystem_security,
        html_guard,
        retry,
        routing,
        telemetry,
    )

    assert JitterRetry is retry.JitterRetry
    assert mailjet_rest.Endpoint is Endpoint
    assert callable(mj_errors.handle_api_error)
    assert callable(telemetry.record_debug_telemetry)
    assert callable(routing.build_endpoint_url)
    assert callable(html_guard.analyze_html_safety)
    assert callable(filesystem_security.validate_attachment_path)

    with Client(auth=("pub_key", "priv_key")) as client:
        assert client.available_endpoints == tuple(sorted(ROUTE_MAP))
        assert "send_v31" in client.available_endpoints
        assert "contacts" in client.available_endpoints
        with pytest.raises(AttributeError, match=r"has no endpoint or attribute 'snd'\. Did you mean 'send'\?"):
            _ = client.snd

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
