"""Shared route tiers, coverage registry, payload builders, and assertions for the live 89-endpoint matrix."""

from __future__ import annotations

import base64
import warnings
from collections.abc import Sequence
from typing import Any, cast

import pytest

from mailjet_rest.routes import DEPRECATION_ADVISORY


LIVE_CREDENTIALS_REASON = "MJ_APIKEY_PUBLIC and MJ_APIKEY_PRIVATE environment variables must be set."
_NONEXISTENT_ID = 999_999_999_999
_MAX_LIVE_LATENCY_SECONDS = 30.0

_NO_LIMIT_SINGLETON_ROUTES: frozenset[str] = frozenset(
    {
        "apikeyaccess",
        "apikeytotals",
        "geostatistics",
        "messagestate",
        "myprofile",
        "parseroute",
        "user",
    }
)

_TIER_A_COLLECTION_ROUTES: tuple[str, ...] = (
    "apikey",
    "apikeyaccess",
    "batchjob",
    "bouncestatistics",
    "campaign",
    "campaigndraft",
    "campaignoverview",
    "clickstatistics",
    "contact",
    "contactdata",
    "contactfilter",
    "contactmetadata",
    "contactslist",
    "contactslistsignup",
    "contactstatistics",
    "dns",
    "eventcallbackurl",
    "geostatistics",
    "listrecipient",
    "listrecipientstatistics",
    "message",
    "messageinformation",
    "messagestate",
    "metasender",
    "myprofile",
    "openinformation",
    "parseroute",
    "sender",
    "template",
    "toplinkclicked",
    "user",
    "useragentstatistics",
)

_TIER_A_V1_COLLECTION_ROUTES: tuple[str, ...] = (
    "images",
    "labels",
    "templates",
    "tokens",
    "v1_templates",
)

# Deprecated routes that still emit DeprecationWarning and are checked for release retirement.
_TIER_B_COLLECTION_ROUTES: tuple[str, ...] = (
    "apikeytotals",
    "campaignstatistics",
    "domainstatistics",
    "liststatistics",
    "messagestatistics",
    "newsletter",
    "openstatistics",
    "senderstatistics",
)

_TIER_B_PARAM_STATS_ROUTES: tuple[str, ...] = (
    "campaigngraphstatistics",
    "graphstatistics",
)

_TIER_B_SUBRESOURCE_PROBES: tuple[tuple[str, str], ...] = (
    ("newsletter_detailcontent", "get"),
    ("newsletter_schedule", "get"),
    ("newsletter_send", "create"),
    ("newsletter_status", "get"),
    ("newsletter_test", "create"),
)

_TIER_C_RETIRED_ROUTES: tuple[str, ...] = (
    "messagesentstatistics",
    "webhook",
)

# Complete registry mapping all 89 ROUTE_MAP keys to test functions in this matrix.
COVERED_LIVE_ROUTES: frozenset[str] = frozenset(
    {
        *_TIER_A_COLLECTION_ROUTES,
        *_TIER_A_V1_COLLECTION_ROUTES,
        *_TIER_B_COLLECTION_ROUTES,
        *_TIER_B_PARAM_STATS_ROUTES,
        *(name for name, _ in _TIER_B_SUBRESOURCE_PROBES),
        *_TIER_C_RETIRED_ROUTES,
        "batch",
        "batchjob_csverror",
        "campaigndraft_detailcontent",
        "campaigndraft_schedule",
        "campaigndraft_send",
        "campaigndraft_status",
        "campaigndraft_test",
        "contact_getcontactslists",
        "contact_managemanycontacts",
        "contact_managecontactslists",
        "contacts",
        "contactslist_csvdata",
        "contactslist_importlist",
        "contactslist_managecontact",
        "contactslist_managemanycontacts",
        "contactslist_verify",
        "csvimport",
        "data_images",
        "data_images_by_type",
        "dns_check",
        "messagehistory",
        "send",
        "send_v31",
        "sender_validate",
        "statcounters",
        "statistics_linkClick",
        "statistics_recipientEsp",
        "template_content_by_type",
        "template_contents",
        "template_contents_lock",
        "template_contents_publish",
        "template_contents_unlock",
        "template_detailcontent",
        "template_update",
        "templates_contents",
    }
)

STATCOUNTERS_FILTERS: dict[str, str] = {
    "CounterSource": "APIKey",
    "CounterTiming": "Message",
    "CounterResolution": "Lifetime",
}

SAFE_CAMPAIGNDRAFT_AND_DOMAIN_PROBES: tuple[tuple[str, str, dict[str, Any]], ...] = (
    ("campaigndraft_detailcontent", "get", {"id": _NONEXISTENT_ID}),
    ("campaigndraft_schedule", "get", {"id": _NONEXISTENT_ID}),
    ("campaigndraft_test", "create", {"id": _NONEXISTENT_ID, "data": {}}),
    ("campaigndraft_send", "create", {"id": _NONEXISTENT_ID, "data": {}}),
    ("sender_validate", "create", {"id": _NONEXISTENT_ID, "data": {}}),
    ("dns_check", "create", {"id": _NONEXISTENT_ID, "data": {}}),
)

_TINY_PNG_B64 = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNkYAAAAAYAAjCB0C8AAAAASUVORK5CYII="

__all__ = [
    "COVERED_LIVE_ROUTES",
    "LIVE_CREDENTIALS_REASON",
    "SAFE_CAMPAIGNDRAFT_AND_DOMAIN_PROBES",
    "STATCOUNTERS_FILTERS",
    "_NO_LIMIT_SINGLETON_ROUTES",
    "assert_expected_deprecation_warning",
    "assert_json_collection_response",
    "assert_no_deprecation_warnings",
    "assert_not_retired_or_disabled",
    "build_send_v31_sandbox_payload",
    "build_v1_image_files_payload",
    "build_v1_template_content_payload",
    "extract_first_id",
]


def assert_not_retired_or_disabled(route_name: str, status_code: int, error_text: str) -> None:
    """Fail immediately when a live endpoint responds with 405/410/5xx or 'unknown resource' drift."""
    lowered = error_text.lower()
    if status_code in {405, 410, 501} or status_code >= 500 or "unknown resource" in lowered:
        pytest.fail(
            f"RELEASE DRIFT DETECTED: Endpoint '{route_name}' appears disabled/retired on Mailjet "
            f"(HTTP {status_code}: {error_text[:200]!r})."
        )


def assert_json_collection_response(route_name: str, resp: Any, elapsed: float) -> dict[str, Any]:
    """Assert HTTP 200, latency budget, JSON object envelope, and list-typed Data field."""
    assert resp.status_code == 200, f"{route_name} returned HTTP {resp.status_code}: {resp.text}"
    assert elapsed < _MAX_LIVE_LATENCY_SECONDS, f"{route_name} latency too high: {elapsed:.2f}s"
    ctype = resp.headers.get("Content-Type", "").lower()
    assert "application/json" in ctype, f"{route_name} unexpected Content-Type: {ctype!r}"
    payload = resp.json()
    assert isinstance(payload, dict), f"{route_name} response JSON is not an object"
    assert "Data" in payload and isinstance(payload["Data"], list), f"{route_name} missing Data array"
    return cast("dict[str, Any]", payload)


def assert_no_deprecation_warnings(caught: Sequence[warnings.WarningMessage]) -> None:
    """Assert zero DeprecationWarning records were emitted."""
    assert not [w for w in caught if issubclass(w.category, DeprecationWarning)]


def assert_expected_deprecation_warning(
    caught: Sequence[warnings.WarningMessage],
    route_name: str | None = None,
) -> None:
    """Assert at least one DeprecationWarning was emitted and match advisory text when requested."""
    depr = [w for w in caught if issubclass(w.category, DeprecationWarning)]
    assert depr, f"Expected DeprecationWarning for '{route_name or 'route'}'"
    if route_name is not None:
        assert DEPRECATION_ADVISORY[route_name] in str(depr[0].message)


def extract_first_id(resp: Any, default: int = _NONEXISTENT_ID) -> int:
    """Return the first record ID from a collection response or fall back to default."""
    data = resp.json().get("Data")
    if data:
        return cast("int", data[0]["ID"])
    return default


def build_send_v31_sandbox_payload() -> dict[str, Any]:
    """Build a non-delivering SandboxMode v3.1 send payload."""
    return {
        "Messages": [
            {
                "From": {"Email": "pilot@mailjet.com", "Name": "Mailjet Pilot"},
                "To": [{"Email": "passenger1@mailjet.com", "Name": "Passenger 1"}],
                "Subject": "Matrix Sandbox v3.1",
                "TextPart": "Sandbox delivery verification",
            }
        ],
        "SandboxMode": True,
    }


def build_v1_template_content_payload() -> dict[str, Any]:
    """Build minimal Content API v1 template content payload."""
    return {
        "Headers": {"Subject": "V1 Matrix"},
        "HtmlPart": "<html><body><p>V1 Matrix</p></body></html>",
        "TextPart": "V1 Matrix",
        "Locale": "en_US",
    }


def build_v1_image_files_payload(img_name: str, *, include_metadata: bool = True) -> dict[str, Any]:
    """Build multipart files payload for v1 data_images and data_images_by_type requests."""
    files: dict[str, Any] = {
        "file": (img_name, base64.b64decode(_TINY_PNG_B64), "image/png"),
    }
    if include_metadata:
        return {
            "metadata": (None, f'{{"name": "{img_name}", "Status": "open"}}', "application/json"),
            **files,
        }
    return files
