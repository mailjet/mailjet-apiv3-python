"""Unit tests for the Mailjet API client routing and internal logic."""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
from pytest import LogCaptureFixture
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.exceptions import RequestException
from requests.exceptions import Timeout as RequestsTimeout

from mailjet_rest._version import __version__
from mailjet_rest.client import (
    ApiError,
    Client,
    Config,
    CriticalApiError,
    TimeoutError,
    prepare_url,
)


@pytest.fixture
def client_offline() -> Client:
    """Return a client with fake credentials for pure offline unit testing."""
    return Client(auth=("fake_public_key", "fake_private_key"), version="v3")


# --- Authentication & Initialization Tests ---


def test_bearer_token_auth_initialization() -> None:
    """Verify that passing a string to auth configures Bearer token (Content API v1)."""
    token = "secret_v1_token_123"
    client = Client(auth=token)

    assert client.session.auth is None
    assert "Authorization" in client.session.headers
    assert client.session.headers["Authorization"] == f"Bearer {token}"


def test_basic_auth_initialization() -> None:
    """Verify that passing a tuple to auth configures Basic Auth (Email API)."""
    client = Client(auth=("public", "private"))
    assert client.session.auth == ("public", "private")
    assert "Authorization" not in client.session.headers


def test_auth_validation_errors() -> None:
    """Verify that malformed auth inputs raise appropriate exceptions (Fail Fast)."""
    with pytest.raises(ValueError, match="Basic auth tuple must contain exactly two"):
        Client(auth=("public", "private", "extra"))  # type: ignore[arg-type]
    with pytest.raises(ValueError, match="Basic auth tuple must contain exactly two"):
        Client(auth=("public",))  # type: ignore[arg-type]

    with pytest.raises(ValueError, match="Bearer token cannot be an empty string"):
        Client(auth="   ")
    with pytest.raises(ValueError, match="Bearer token cannot be an empty string"):
        Client(auth="")

    with pytest.raises(ValueError, match="Header Injection risk"):
        Client(auth="my_token\r\ninjected_header: bad")
    with pytest.raises(ValueError, match="Header Injection risk"):
        Client(auth="my_token\ninjected")

    with pytest.raises(TypeError, match="Invalid auth type"):
        Client(auth=12345)  # type: ignore[arg-type]
    with pytest.raises(TypeError, match="Invalid auth type"):
        Client(auth=["key", "secret"])  # type: ignore[arg-type]


# --- Dynamic API Versioning Tests ---


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v99_future"])
def test_dynamic_versions_standard_rest(api_version: str) -> None:
    """Test standard REST API URLs adapt to any version string."""
    client = Client(auth=("a", "b"), version=api_version)
    assert (
        client.contact._build_url()
        == f"https://api.mailjet.com/{api_version}/REST/contact"
    )
    assert (
        client.contact_managecontactslists._build_url(id=456)
        == f"https://api.mailjet.com/{api_version}/REST/contact/456/managecontactslists"
    )


def test_dynamic_versions_content_api_v1_routing() -> None:
    """Test that Content API v1 routing uses /REST/ and uses slashes for sub-actions."""
    client_v1 = Client(auth="token", version="v1")
    assert client_v1.templates._build_url() == "https://api.mailjet.com/v1/REST/templates"
    assert client_v1.data_images._build_url(id=123) == "https://api.mailjet.com/v1/data/images/123"
    assert (
        client_v1.template_contents_lock._build_url(id=1) == "https://api.mailjet.com/v1/REST/template/1/contents/lock"
    )


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v99_future"])
def test_dynamic_versions_send_api(api_version: str) -> None:
    """Test Send API URLs correctly adapt to any version string without the REST prefix."""
    client = Client(auth=("a", "b"), version=api_version)
    assert client.send._build_url() == f"https://api.mailjet.com/{api_version}/send"


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v99_future"])
def test_dynamic_versions_data_api(api_version: str) -> None:
    """Test DATA API URLs correctly adapt to any version string."""
    client = Client(auth=("a", "b"), version=api_version)
    assert (
        client.contactslist_csvdata._build_url(id=123)
        == f"https://api.mailjet.com/{api_version}/DATA/contactslist/123/CSVData/text:plain"
    )


def test_routing_content_api(client_offline: Client) -> None:
    """Test older Content API routing with sub-actions."""
    assert (
        client_offline.template_detailcontent._build_url(id=123)
        == "https://api.mailjet.com/v3/REST/template/123/detailcontent"
    )


def test_send_api_v3_bad_path_routing(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Send API v3 handles bad payloads gracefully at the routing level."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert method == "POST"
        assert url == "https://api.mailjet.com/v3/send"
        resp = requests.Response()
        resp.status_code = 400
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    result = client_offline.send.create(data={})
    assert result.status_code == 400


def test_content_api_bad_path_routing(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify Content API routes correctly even when invalid operations are attempted."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert url == "https://api.mailjet.com/v3/REST/template/999/detailcontent"
        resp = requests.Response()
        resp.status_code = 404
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    result = client_offline.template_detailcontent.get(id=999)
    assert result.status_code == 404


def test_statcounters_endpoint_routing(client_offline: Client, monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that statcounters (Email API Data & Stats) is routed correctly as per README."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert method == "GET"
        assert url == "https://api.mailjet.com/v3/REST/statcounters"
        assert kwargs.get("params") == {
            "CounterSource": "Campaign",
            "CounterTiming": "Message",
            "CounterResolution": "Lifetime",
        }
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    filters = {
        "CounterSource": "Campaign",
        "CounterTiming": "Message",
        "CounterResolution": "Lifetime",
    }
    result = client_offline.statcounters.get(filters=filters)
    assert result.status_code == 200


# --- HTTP Methods & Execution Coverage Tests ---

def test_http_methods_and_timeout(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mock the session request to hit standard wrapper methods and fallback parameters."""
    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    resp_get = client_offline.contact.get(id=1, filters={"limit": 1})
    assert resp_get.status_code == 200

    resp_create = client_offline.contact.create(data={"Name": "Test"}, id=1)
    assert resp_create.status_code == 200

    resp_update = client_offline.contact.update(id=1, data={"Name": "Update"})
    assert resp_update.status_code == 200

    resp_delete = client_offline.contact.delete(id=1)
    assert resp_delete.status_code == 200

    resp_direct = client_offline.contact(
        method="GET", headers={"X-Custom": "1"}, timeout=None
    )
    assert resp_direct.status_code == 200


def test_client_coverage_edge_cases(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicitly hit partial branches (BrPart) to achieve 100% coverage."""
    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp
    monkeypatch.setattr(client_offline.session, "request", mock_request)

    assert (
        client_offline.contactslist_csvdata._build_url()
        == "https://api.mailjet.com/v3/DATA/contactslist"
    )
    assert (
        client_offline.contactslist_csverror._build_url()
        == "https://api.mailjet.com/v3/DATA/contactslist"
    )

    client_offline.contact(action_id=999)
    client_offline.contact.get(filter={"Email": "test@test.com"})
    client_offline.contact.get(timeout=30)

    client_offline.contact.create(data="raw,string,data")
    client_offline.contact.create(data=[{"Email": "test@test.com"}])

    headers = client_offline.contact._build_headers(custom_headers={"X-Test": "1"})
    assert headers["X-Test"] == "1"

    client_offline.contact.get(filters={"limit": 1}, filter={"ignored": "legacy"})


def test_send_api_v3_1_template_language_variables(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Verify TemplateLanguage and Variables serialization (Issue #97)."""
    client_v31 = Client(auth=("a", "b"), version="v3.1")

    def mock_request(
        method: str, url: str, data: str | bytes | None = None, **kwargs: Any
    ) -> requests.Response:
        assert data is not None
        assert isinstance(data, str)
        assert '"TemplateLanguage": true' in data
        assert '"Variables": {"name": "John Doe"}' in data

        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_v31.session, "request", mock_request)

    payload = {
        "Messages": [
            {
                "TemplateLanguage": True,
                "Variables": {"name": "John Doe"},
            }
        ]
    }
    result = client_v31.send.create(data=payload)
    assert result.status_code == 200


def test_api_call_exceptions_and_logging(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    """Verify that network exceptions are mapped correctly and HTTP states are logged."""

    caplog.set_level(logging.DEBUG, logger="mailjet_rest.client")

    def mock_timeout(*args: Any, **kwargs: Any) -> None:
        raise RequestsTimeout("Mocked timeout")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)
    with pytest.raises(TimeoutError, match="Request to Mailjet API timed out"):
        client_offline.contact.get()
    assert "Timeout Error" in caplog.text

    def mock_connection_error(*args: Any, **kwargs: Any) -> None:
        raise RequestsConnectionError("Mocked connection")

    monkeypatch.setattr(client_offline.session, "request", mock_connection_error)
    with pytest.raises(CriticalApiError, match="Connection to Mailjet API failed"):
        client_offline.contact.get()
    assert "Connection Error" in caplog.text

    def mock_request_exception(*args: Any, **kwargs: Any) -> None:
        raise RequestException("Mocked general error")

    monkeypatch.setattr(client_offline.session, "request", mock_request_exception)
    with pytest.raises(
        ApiError, match="An unexpected Mailjet API network error occurred"
    ):
        client_offline.contact.get()
    assert "Request Exception" in caplog.text

    def mock_success(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_success)
    caplog.clear()
    client_offline.contact.get()
    assert "API Success 200" in caplog.text

    def mock_error_response(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 400
        resp._content = b"Bad Request"
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_error_response)
    caplog.clear()
    client_offline.contact.get()
    assert "API Error 400" in caplog.text

    def mock_type_error(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = None  # type: ignore[assignment]
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_type_error)
    caplog.clear()
    client_offline.contact.get()
    assert "API Success None" in caplog.text


# --- Config & Initialization Tests ---

def test_client_custom_version() -> None:
    client = Client(auth=("a", "b"), version="v3.1")
    assert client.config.version == "v3.1"
    assert client.config["send"][0] == "https://api.mailjet.com/v3.1/send"


def test_user_agent() -> None:
    client = Client(auth=("a", "b"), version="v3.1")
    assert client.config.user_agent == f"mailjet-apiv3-python/v{__version__}"


def test_config_getitem_all_branches() -> None:
    """Explicitly test every fallback branch inside the Config dictionary-access implementation."""
    config = Config()

    url, headers = config["send"]
    assert "v3/send" in url

    url, headers = config["contactslist_csvdata"]
    assert "v3/DATA/contactslist" in url
    assert headers["Content-Type"] == "text/plain"

    url, headers = config["contactslist_csverror"]
    assert "v3/DATA/contactslist" in url
    assert headers["Content-type"] == "application/json"

    # Test v1 manual access via config lookup
    config_v1 = Config(version="v1")
    url, headers = config_v1["templates"]
    assert url == "https://api.mailjet.com/v1/REST/templates"


# --- Legacy Functionality Coverage Tests ---

def test_legacy_action_id_fallback(client_offline: Client) -> None:
    assert (
        client_offline.contact._build_url(id=999)
        == "https://api.mailjet.com/v3/REST/contact/999"
    )


def test_prepare_url_headers_and_url() -> None:
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    name = re.sub(r"[A-Z]", prepare_url, "contactManagecontactslists")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"


def test_prepare_url_mixed_case_input() -> None:
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "contact")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"


def test_prepare_url_empty_input() -> None:
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"


def test_prepare_url_with_numbers_input_bad() -> None:
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "contact1Managecontactslists1")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact1"


def test_prepare_url_leading_trailing_underscores_input_bad() -> None:
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "_contactManagecontactslists_")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"
