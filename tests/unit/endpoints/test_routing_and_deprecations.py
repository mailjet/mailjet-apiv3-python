"""Unit tests for Mailjet endpoint URL routing, registry routes, headers, and legacy deprecations."""

from __future__ import annotations

import logging
import re
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
from requests.exceptions import RequestException

from mailjet_rest.client import BaseClient, Client, Config
from mailjet_rest.endpoint import BaseEndpoint
from mailjet_rest.errors import MailjetApiError
from mailjet_rest.routes import DEPRECATION_ADVISORY, ROUTE_MAP
from mailjet_rest.utils.guardrails import SecurityGuard
from mailjet_rest.utils.routing import (
    build_endpoint_headers,
    build_endpoint_url,
    cast_query_param,
    emit_deprecation_if_needed,
    external_stacklevel,
    normalize_stream_filters,
    split_endpoint_parts,
)


# ==========================================
# 1. Dynamic & Registry Route Resolution
# ==========================================


@pytest.mark.parametrize(
    ("version", "resource", "expected_path"),
    [
        ("v1", "templates", "v1/REST/templates"),
        ("v3", "contact", "v3/REST/contact"),
        ("v3.1", "message", "v3.1/REST/message"),
        ("v99_future", "newresource", "v99_future/REST/newresource"),
    ],
)
def test_dynamic_versions_standard_rest(
    version: str, resource: str, expected_path: str, client_offline: Client
) -> None:
    """Verify REST URL construction dynamically respects the configured API version."""
    client_offline.config.version = version
    endpoint = getattr(client_offline, resource)
    url = endpoint._build_url()
    assert url == f"https://api.mailjet.com/{expected_path}"


def test_dynamic_versions_content_api_v1_routing(client_offline: Client) -> None:
    """Verify Content API (v1) specific routes construct correctly."""
    client_offline.config.version = "v1"
    with pytest.warns(DeprecationWarning, match="templates_contents"):
        url = client_offline.templates_contents._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents"


def test_dynamic_versions_content_api_v1_complex_routing(client_offline: Client) -> None:
    """Verify deeply nested Content API routes construct correctly using split action."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_types._build_url(id_val=123, action_id="P")
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/types/P"


@pytest.mark.filterwarnings("ignore:Mailjet API Ambiguity:DeprecationWarning")
@pytest.mark.parametrize(
    "version",
    ["v1", "v3", "v3.1", "v99_future"],
)
def test_dynamic_versions_send_api(version: str, client_offline: Client) -> None:
    """Verify the Send API explicitly bypasses the /REST/ prefix across all versions."""
    client_offline.config.version = version
    url = client_offline.send._build_url()
    assert url == f"https://api.mailjet.com/{version}/send"


def test_send_api_v3_bad_path_routing(client_offline: Client) -> None:
    """Verify that unexpected operations on the Send API still attempt to route consistently."""
    client_offline.config.version = "v3"
    url = client_offline.send._build_url()
    assert url == "https://api.mailjet.com/v3/send"


def test_content_api_bad_path_routing(client_offline: Client) -> None:
    """Verify that deeply nested paths format correctly via dynamic fallback logic."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_fakeaction._build_url(id_val=123)
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/fakeaction"


def test_route_strategy_legacy_parity(client_offline: Client) -> None:
    """Verify declarative routes maintain exact legacy URL formatting."""
    client_offline.config.version = "v1"
    url = client_offline.templates_contents_types._build_url(id_val=123, action_id="P")
    assert url == "https://api.mailjet.com/v1/REST/templates/123/contents/types/P"


def test_statcounters_endpoint_routing(client_offline: Client) -> None:
    """Verify statistical routing bypasses standard logic."""
    client_offline.config.version = "v3"
    url = client_offline.statcounters._build_url()
    assert url == "https://api.mailjet.com/v3/REST/statcounters"


def test_camel_case_to_dash_routing(client_offline: Client) -> None:
    """Verify that CamelCase endpoints correctly translate to dashed paths (e.g., linkClick -> link-click)."""
    url = client_offline.statistics_linkClick._build_url()
    assert url == "https://api.mailjet.com/v3/REST/statistics/link-click"


def test_legacy_action_id_fallback(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that if 'id' is omitted but 'action_id' is passed, it shifts to the primary ID correctly."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert "/REST/contact/123" in url
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    client_offline.contact.get(action_id=123)


def test_endpoint_precomputes_routing_strings(client_offline: Client) -> None:
    """Verify that Endpoint pre-computes routing strings to save CPU cycles."""
    endpoint = getattr(client_offline, "Contact_Data")
    assert endpoint._name_lower == "contact_data"
    assert endpoint._action_parts == ["contact", "data"]
    assert endpoint._resource_lower == "contact"


def test_endpoint_headers_merge_safely(client_offline: Client) -> None:
    """Verify that endpoint header building unpacks safely without mutating the base proxies."""
    endpoint = client_offline.contact
    merged_headers = endpoint._build_headers({"X-Custom-Header": "SafeValue"})
    assert merged_headers["Content-Type"] == "application/json"
    assert merged_headers["X-Custom-Header"] == "SafeValue"


@pytest.mark.parametrize(
    ("endpoint_name", "kwargs", "expected_url"),
    [
        ("send", {}, "https://api.mailjet.com/v3/send"),
        ("contact", {}, "https://api.mailjet.com/v3/REST/contact"),
        ("contact", {"id_val": 123}, "https://api.mailjet.com/v3/REST/contact/123"),
        ("campaign", {}, "https://api.mailjet.com/v3/REST/campaign"),
        ("tokens", {}, "https://api.mailjet.com/v1/REST/tokens"),
        (
            "template_content_by_type",
            {"id_val": 100, "action_id": "html"},
            "https://api.mailjet.com/v1/REST/templates/100/contents/types/html",
        ),
    ],
)
def test_all_registry_routes(
    client_offline: Client, endpoint_name: str, kwargs: dict[str, Any], expected_url: str
) -> None:
    """Verify that every endpoint in the registry constructs the correct URL and handles URI templating."""
    endpoint = getattr(client_offline, endpoint_name)
    url = endpoint._build_url(**kwargs)
    assert url == expected_url


def test_registry_uri_interpolation_path_traversal_cwe22(client_offline: Client) -> None:
    """Verify that malicious dynamic values injected into URI templates are safely URL-encoded (CWE-22)."""
    malicious_id = "../delete"
    endpoint = client_offline.template_update
    # Expect the ValueError we now actively throw against CWE-22 tokens
    with (
        pytest.warns(DeprecationWarning, match="template_update"),
        pytest.raises(ValueError, match="Path traversal attempt"),
    ):
        endpoint._build_url(id_val=malicious_id)


# ==========================================
# 2. Legacy Kwargs, Encodings & Deprecations
# ==========================================


def test_legacy_kwargs_emit_deprecation_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that using ensure_ascii or data_encoding in Client.create emits a warning."""
    client = Client(auth=("a", "b"), version="v3")

    def mock_request(method: str, url: str, data: Any = None, json: Any = None, **kwargs: Any) -> requests.Response:
        assert "ensure_ascii" not in kwargs  # Should be consumed by the wrapper
        assert data is not None or json is not None

        if data is not None:
            assert "\\u" not in data if isinstance(data, str) else True

        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client.session, "request", mock_request)

    # Triggering via create()
    with pytest.warns(DeprecationWarning, match="'ensure_ascii' and 'data_encoding' are deprecated"):
        client.contact.create(data={"Name": "Test"}, ensure_ascii=False)

    # Triggering via update()
    with pytest.warns(DeprecationWarning, match="'ensure_ascii' and 'data_encoding' are deprecated"):
        client.contact.update(id=1, data={"Name": "Test"}, ensure_ascii=False)


def test_legacy_encoding_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that explicitly passing data_encoding actually transcodes the payload to bytes."""
    client = Client(auth=("a", "b"), version="v3")

    def mock_request(method: str, url: str, data: Any = None, **kwargs: Any) -> requests.Response:
        assert isinstance(data, bytes)  # It was encoded!
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client.session, "request", mock_request)

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        client.contact.create(data={"Name": "Test"}, data_encoding="utf-8")


@pytest.mark.parametrize("route_name,replacement", DEPRECATION_ADVISORY.items())
def test_deprecated_endpoint_emits_warning(route_name: str, replacement: str) -> None:
    """Ensure every registered deprecated route emits an actionable DeprecationWarning."""
    client = Client(auth=("key", "secret"))
    endpoint = getattr(client, route_name)

    expected_msg = f"Endpoint '{route_name}' is deprecated in the Mailjet API. Migrate to '{replacement}'."
    with pytest.warns(DeprecationWarning, match=re.escape(expected_msg)):
        # Passing id_val=1 satisfies endpoints requiring an '{id}' URI parameter
        # while safely appending as an ID segment for unparameterized routes
        endpoint._build_url(id_val=1)


# ==========================================
# 3. Security Routing, OpenAPI Routes & Helper Mutants
# ==========================================


def test_routing_query_fragment_delete_5xx_and_warning_stacklevel() -> None:
    """Query/fragment delimiters, blank/bool delete IDs, 5xx MailjetApiError, and external stacklevel work."""
    with pytest.raises(ValueError, match="Query or fragment delimiters"):
        SecurityGuard.sanitize_segment("123?admin=true")

    with pytest.raises(ValueError, match="Query or fragment delimiters"):
        SecurityGuard.sanitize_segment("123%23frag")

    client = Client(auth=("pub_key", "priv_key"))
    for bad_id in ("", "   ", None, True, False):
        with pytest.raises(ValueError, match="Endpoint.delete\\(\\) requires"):
            client.contact.delete(id=bad_id)  # type: ignore[arg-type]

    resp_503 = MagicMock(status_code=503, text="Service Unavailable")
    resp_503.json.side_effect = ValueError("not json")
    with pytest.raises(MailjetApiError) as exc_info:
        Client._handle_api_error(RequestException("503", response=resp_503))
    assert exc_info.value.status_code == 503
    assert exc_info.value.response_body == "Service Unavailable"

    with pytest.warns(DeprecationWarning, match="Endpoint 'newsletter' is deprecated") as caught:
        client.newsletter._build_url()
    if "mutants" not in Path(__file__).parts:
        assert Path(caught[0].filename).resolve() == Path(__file__).resolve()


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


def test_build_endpoint_headers_lowercase_content_type_overrides_default() -> None:
    """Lowercase 'content-type' override must replace default 'Content-Type' without duplicate keys."""
    merged = build_endpoint_headers("contact", {"content-type": "application/x-www-form-urlencoded"})
    ct_keys = [k for k in merged if k.lower() == "content-type"]
    assert ct_keys == ["content-type"]
    assert merged["content-type"] == "application/x-www-form-urlencoded"


def test_csverror_headers_304_not_redirect_and_messagesentstatistics_deprecation(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Verify *_csverror sends text/csv, HTTP 304 skips redirect warning/audit, and messagesentstatistics warns."""
    assert build_endpoint_headers("batchjob_csverror") == {"Content-Type": "text/csv"}
    assert build_endpoint_headers("batchjob_csverror", {"content-type": "text/plain"}) == {"content-type": "text/plain"}

    with Client(auth=("pub_key", "priv_key")) as client:
        assert client.batchjob_csverror._build_headers() == {"Content-Type": "text/csv"}  # ruff: ignore[private-member-access]
        with pytest.warns(DeprecationWarning, match="Migrate to 'statcounters'"):
            assert client.messagesentstatistics._build_url() == "https://api.mailjet.com/v3/REST/messagesentstatistics"  # ruff: ignore[private-member-access]

    url = "https://api.mailjet.com/v3/REST/contact/123"
    resp_304 = MagicMock(status_code=304)
    with caplog.at_level(logging.WARNING, logger="mailjet_rest.client"), patch("sys.audit") as mock_audit:
        BaseClient._check_unexpected_redirect(url, resp_304)  # ruff: ignore[private-member-access]
    assert not any("304" in rec.message for rec in caplog.records)
    assert not any(
        call.args and call.args[0] == "mailjet.security.unexpected_redirect" for call in mock_audit.call_args_list
    )

    for status_code in (301, 302, 307, 308):
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="mailjet_rest.client"), patch("sys.audit") as mock_audit:
            BaseClient._check_unexpected_redirect(url, MagicMock(status_code=status_code))  # ruff: ignore[private-member-access]
        assert any(f"({status_code})" in rec.message for rec in caplog.records)
        mock_audit.assert_any_call("mailjet.security.unexpected_redirect", url, status_code)


def test_base_endpoint_and_routing_helpers_mutants() -> None:
    """Cover BaseEndpoint._resolve_registry_route, _resolve_dynamic_route, and routing helpers."""
    client = MagicMock()
    base = BaseEndpoint(client, "contact_getcontactslists")

    url, res_id, act_id = base._resolve_registry_route("https://api.mailjet.com", "v3", 42, 7)
    assert url == "https://api.mailjet.com/v3/REST/contact/42/getcontactslists"
    assert res_id is None
    assert act_id == 7

    dyn = BaseEndpoint(client, "contactslist_csvdata")
    d_url, d_id, d_act = dyn._resolve_dynamic_route("https://api.mailjet.com", "v3", 10, "raw")
    assert d_url == "https://api.mailjet.com/v3/DATA/contactslist/10/CSVData/text:plain"
    assert d_id is None
    assert d_act == "raw"

    # Routing: split_endpoint_parts, versions, trailing slash strip, stream filters Limit pop
    assert split_endpoint_parts("contact") == ("contact", "contact", ["contact"])
    assert split_endpoint_parts("tpl_UserInfo") == ("tpl_userinfo", "tpl", ["tpl", "user-info"])
    for ver in ("v1", "v3", "v3.1", "v4"):
        with patch("mailjet_rest.utils.routing.SecurityGuard.sanitize_segment", wraps=lambda s: s) as spy_seg:
            built = build_endpoint_url("contact", "contact", "contact", ["contact"], "https://api.mailjet.com/", ver)
            assert built == f"https://api.mailjet.com/{ver}/REST/contact"
            spy_seg.assert_not_called()
    assert cast_query_param("s", ["a", "b"]) == ["a", "b"]
    norm_f, norm_off = normalize_stream_filters({"Limit": "99", "Offset": "5"}, 50)
    assert norm_f == {"Limit": 50, "Offset": "5"}
    assert norm_off == 5
    assert external_stacklevel() >= 1
    with pytest.warns(DeprecationWarning):
        emit_deprecation_if_needed("newsletter", "newsletter")
