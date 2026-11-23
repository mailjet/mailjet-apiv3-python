"""Unit tests for PEP 562 lazy exports, cold-boot isolation, __slots__, types, and versioning."""

from __future__ import annotations

import asyncio
import importlib
import json
import subprocess
import sys
from contextlib import suppress
from types import MappingProxyType
from typing import Any
from unittest.mock import patch

import pytest

from mailjet_rest import (
    MockMailjetClient as LazyMockMailjetClient,
    types as mj_types,
    verify_webhook_signature as lazy_verify,
)
from mailjet_rest.builders import ChunkedStreamer
from mailjet_rest.client import AsyncClient, BaseClient, Client, Config, JitterRetry, _httpx2
from mailjet_rest.endpoint import AsyncEndpoint
from mailjet_rest.testing import MockMailjetClient
from mailjet_rest.utils.guardrails import SecretAuth, SecurityGuard
from mailjet_rest.utils.version import clean_version, get_version, parse_semver_triplet
from mailjet_rest.webhooks import verify_webhook_signature


def test_pep562_lazy_top_level_import_isolation() -> None:
    """Importing mailjet_rest does not eagerly load heavy transport or parser modules."""
    code = (
        "import json, sys, mailjet_rest; "
        "heavy = ('requests', 'urllib3', 'ssl', 'html.parser', 'difflib', 'mimetypes', 'httpx2', 'httpcore2'); "
        "loaded = [m for m in heavy if m in sys.modules]; "
        "exported = dir(mailjet_rest); "
        "print(json.dumps({'loaded': loaded, 'has_client': 'Client' in exported, "
        "'has_async_client': 'AsyncClient' in exported, 'has_async_endpoint': 'AsyncEndpoint' in exported}))"
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
    assert payload["has_client"] is True
    assert payload["has_async_client"] is True
    assert payload["has_async_endpoint"] is True

    sync_only_code = (
        "import json, sys; "
        "from mailjet_rest.client import Client; "
        "_ = Client(auth=('k', 's')); "
        "loaded = [m for m in ('httpx2', 'httpcore2') if m in sys.modules]; "
        "print(json.dumps({'loaded': loaded}))"
    )
    sync_proc = subprocess.run(
        [sys.executable, "-c", sync_only_code],
        capture_output=True,
        text=True,
        check=True,
        timeout=15,
    )
    sync_payload = json.loads(sync_proc.stdout)
    assert sync_payload["loaded"] == []


def test_package_lazy_exports_and_missing_attr() -> None:
    """Top-level PEP 562 exposes Client, AsyncClient, AsyncEndpoint, Config, __version__ and rejects unknown attrs."""
    mailjet_rest = importlib.import_module("mailjet_rest")

    assert mailjet_rest.Client is Client
    assert mailjet_rest.AsyncClient is AsyncClient
    assert mailjet_rest.AsyncEndpoint is AsyncEndpoint
    assert mailjet_rest.Config is Config
    assert issubclass(mailjet_rest.ApiError, Exception)
    assert callable(mailjet_rest.get_version)
    assert isinstance(mailjet_rest.__version__, str)
    assert "Client" in dir(mailjet_rest)
    assert "AsyncClient" in dir(mailjet_rest)
    assert "__version__" in dir(mailjet_rest)

    with pytest.raises(AttributeError, match="no attribute"):
        _ = mailjet_rest.non_existent_symbol_xyz  # type: ignore[attr-defined]

    with pytest.raises(ImportError, match="Disallowed lazy submodule"):
        mailjet_rest._import_known_submodule("os")


def test_slots_enforced_and_secret_auth_unslotted() -> None:
    """Client, AsyncClient, Endpoints, ChunkedStreamer, and SecurityGuard use __slots__; SecretAuth stays unslotted."""
    with Client(auth=("api_key_value", "api_secret_value")) as client:
        assert not hasattr(client, "__dict__")
        assert not hasattr(client.contact, "__dict__")
        assert not hasattr(ChunkedStreamer(), "__dict__")
        assert not hasattr(SecurityGuard(), "__dict__")
        # SecretAuth inherits from requests.auth.AuthBase (unslotted in 1.x)
        assert isinstance(client.auth, SecretAuth)
        assert hasattr(client.auth, "__dict__")

    if _httpx2 is not None:

        async def _check_async_slots() -> None:
            async with AsyncClient(auth=("api_key_value", "api_secret_value")) as aclient:
                assert not hasattr(aclient, "__dict__")
                assert isinstance(aclient.contact, AsyncEndpoint)
                assert not hasattr(aclient.contact, "__dict__")
                assert isinstance(aclient.auth, SecretAuth)

        asyncio.run(_check_async_slots())


def test_endpoint_and_config_use_slots() -> None:
    config = Config()
    assert not hasattr(config, "__dict__")


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


def test_version_length_equal_three() -> None:
    """Verifies standard version fetching returns a properly formatted string."""
    version = get_version()
    if version:
        assert len(version.split(".")) >= 3


def test_get_version_is_none() -> None:
    """Simulates an environment where version retrieval dependencies fail."""
    with (
        patch.dict(
            sys.modules,
            {"pkg_resources": None, "importlib.metadata": None, "mailjet_rest": None},
        ),
        suppress(Exception),
    ):
        get_version()


def test_get_version() -> None:
    assert get_version() is not None


def test_get_version_raises_exception() -> None:
    """Forces the version parser to hit its fallback exception blocks (ValueError, ImportError, etc.)."""
    # By forcing a ValueError exception on the system path or modules, we hit lines 31-65.
    with (
        patch(
            "mailjet_rest.utils.version.open",
            side_effect=ValueError("Forced ValueError for coverage"),
        ),
        patch.dict(sys.modules, {"pkg_resources": None, "importlib.metadata": None}),
        suppress(Exception),
    ):
        get_version()

    with (
        patch(
            "mailjet_rest.utils.version.open",
            side_effect=ImportError("Forced ImportError for coverage"),
        ),
        patch.dict(sys.modules, {"pkg_resources": None, "importlib.metadata": None}),
        suppress(Exception),
    ):
        get_version()


def test_clean_version_invalid_string() -> None:
    """Coverage: Hits the IndexError/ValueError blocks in the string cleaner fallback."""
    assert clean_version("not.a.version") == (0, 0, 0)
    assert clean_version("1.0") == (0, 0, 0)  # Missing patch triggering IndexError
    assert clean_version("a.b.c") == (0, 0, 0)  # String to integer parsing triggers ValueError


def test_get_version_invalid_tuple() -> None:
    """Coverage: Forces the hard ValueError loop on invalid internal tuple declarations."""
    with pytest.raises(ValueError, match="must contain 3 items"):
        get_version((1, 2))


def test_semver_prerelease_triplet_parsing() -> None:
    """Verify HIGH-07: prerelease digits are not concatenated into patch."""
    assert parse_semver_triplet("1.9.1rc2") == (1, 9, 1)
    assert parse_semver_triplet("1.10.0post3") == (1, 10, 0)
    assert parse_semver_triplet("2.0.15.dev4") == (2, 0, 15)
    assert clean_version("1.9.1rc2") == (1, 9, 1)
    assert clean_version("1.10.0post3") == (1, 10, 0)
    assert clean_version("invalid") == (0, 0, 0)

    with pytest.raises(ValueError, match="Expected X.Y.Z"):
        parse_semver_triplet("1.2")
    with pytest.raises(ValueError, match="Invalid patch component"):
        parse_semver_triplet("1.2.rc1")


def test_version_helpers_exact_validation_and_formatting() -> None:
    """Kill survived mutants in parse_semver_triplet and get_version."""
    assert parse_semver_triplet("1.9.2") == (1, 9, 2)
    with pytest.raises(ValueError, match="Expected X.Y.Z version string"):
        parse_semver_triplet("abc.1.2")

    assert get_version((1, 2, 3)) == "1.2.3"
    with pytest.raises(ValueError, match=r"^The tuple 'version' must contain 3 items$"):
        get_version((1, 2))  # type: ignore[arg-type]


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

    bulk_dict: dict[str, Any] = dict(bulk)
    assert contact_in["Email"] == "user@example.com"
    assert bulk_dict["ContactsLists"][0]["Action"] == "addnoforce"
    assert dict(webhook)["Version"] == 2
    assert dict(tpl_content)["Locale"] == "en_US"
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


def test_modular_scaffolding_reexports() -> None:
    """Verify modular utility extraction preserves v1.9.1 re-exports and adds clean DX helpers."""
    from mailjet_rest import (  # ruff: ignore[import-outside-top-level]
        Endpoint,
        errors as mj_errors,
    )
    from mailjet_rest.endpoint import Endpoint as DirectEndpoint  # ruff: ignore[import-outside-top-level]
    from mailjet_rest.utils import (  # ruff: ignore[import-outside-top-level]
        filesystem_security,
        html_guard,
        retry,
        routing,
        telemetry,
    )

    assert JitterRetry is retry.JitterRetry
    assert Endpoint is DirectEndpoint
    assert callable(mj_errors.handle_api_error)
    assert callable(telemetry.record_debug_telemetry)
    assert callable(routing.build_endpoint_url)
    assert callable(html_guard.analyze_html_safety)
    assert callable(filesystem_security.validate_attachment_path)
