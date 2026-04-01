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


# --- Dynamic API Versioning Tests ---

@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v4", "v99_future"])
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


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v4", "v99_future"])
def test_dynamic_versions_send_api(api_version: str) -> None:
    """Test Send API URLs correctly adapt to any version string without the REST prefix."""
    client = Client(auth=("a", "b"), version=api_version)
    assert client.send._build_url() == f"https://api.mailjet.com/{api_version}/send"


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v4", "v99_future"])
def test_dynamic_versions_data_api(api_version: str) -> None:
    """Test DATA API URLs correctly adapt to any version string."""
    client = Client(auth=("a", "b"), version=api_version)
    assert (
        client.contactslist_csvdata._build_url(id=123)
        == f"https://api.mailjet.com/{api_version}/DATA/contactslist/123/CSVData/text:plain"
    )


def test_dynamic_versions_sms_api_adaptive() -> None:
    """Test that SMS API promotes v3 to v4 safely, but respects explicit future versions."""
    client_v3 = Client(auth=("a", "b"), version="v3")
    assert client_v3.sms_send._build_url() == "https://api.mailjet.com/v4/sms-send"
    client_v4 = Client(auth=("a", "b"), version="v4")
    assert client_v4.sms_send._build_url() == "https://api.mailjet.com/v4/sms-send"
    client_v5 = Client(auth=("a", "b"), version="v5")
    assert client_v5.sms_send._build_url() == "https://api.mailjet.com/v5/sms-send"


def test_routing_content_api(client_offline: Client) -> None:
    """Test Content API routing with sub-actions."""
    assert (
        client_offline.template_detailcontent._build_url(id=123)
        == "https://api.mailjet.com/v3/REST/template/123/detailcontent"
    )


def test_sms_api_v4_routing(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Verify SMS API explicitly promotes the URL to /v4/sms-send regardless of v3 setting."""

    def mock_request(method: str, url: str, **kwargs: Any) -> requests.Response:
        assert url == "https://api.mailjet.com/v4/sms-send"
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)
    client_offline.sms_send.create(data={"Text": "Hello", "To": "+123"})


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

    # AAA Pattern: Act then Assert to avoid side-effects in asserts
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

    # Hits the `elif "filter" in kwargs` branch
    client_offline.contact.get(filters={"limit": 1}, filter={"ignored": "legacy"})


def test_api_call_exceptions_and_logging(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch, caplog: LogCaptureFixture
) -> None:
    """Verify that network exceptions are mapped correctly and HTTP states are logged."""

    caplog.set_level(logging.DEBUG, logger="mailjet_rest.client")

    # 1. Test TimeoutError mapping
    def mock_timeout(*args: Any, **kwargs: Any) -> None:
        raise RequestsTimeout("Mocked timeout")

    monkeypatch.setattr(client_offline.session, "request", mock_timeout)
    with pytest.raises(TimeoutError, match="Request to Mailjet API timed out"):
        client_offline.contact.get()
    assert "Timeout Error" in caplog.text

    # 2. Test CriticalApiError mapping (Connection Error)
    def mock_connection_error(*args: Any, **kwargs: Any) -> None:
        raise RequestsConnectionError("Mocked connection")

    monkeypatch.setattr(client_offline.session, "request", mock_connection_error)
    with pytest.raises(CriticalApiError, match="Connection to Mailjet API failed"):
        client_offline.contact.get()
    assert "Connection Error" in caplog.text

    # 3. Test generic ApiError mapping
    def mock_request_exception(*args: Any, **kwargs: Any) -> None:
        raise RequestException("Mocked general error")

    monkeypatch.setattr(client_offline.session, "request", mock_request_exception)
    with pytest.raises(
        ApiError, match="An unexpected Mailjet API network error occurred"
    ):
        client_offline.contact.get()
    assert "Request Exception" in caplog.text

    # 4. Success log
    def mock_success(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_success)
    caplog.clear()
    client_offline.contact.get()
    assert "API Success 200" in caplog.text

    # 5. Error log
    def mock_error_response(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 400
        resp._content = b"Bad Request"
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_error_response)
    caplog.clear()
    client_offline.contact.get()
    assert "API Error 400" in caplog.text

    # 6. TypeError fallback branch for status_code
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
    """Verify that setting a custom version accurately overrides defaults."""
    client = Client(auth=("a", "b"), version="v3.1")
    assert client.config.version == "v3.1"
    assert client.config["send"][0] == "https://api.mailjet.com/v3.1/send"


def test_user_agent() -> None:
    """Verify that the user agent is properly formatted with the package version."""
    client = Client(auth=("a", "b"), version="v3.1")
    assert client.config.user_agent == f"mailjet-apiv3-python/v{__version__}"


def test_config_getitem_all_branches() -> None:
    """Explicitly test every fallback branch inside the Config dictionary-access implementation."""
    config = Config()

    url, headers = config["sms_send"]
    assert "v4/sms-send" in url

    url, headers = config["send"]
    assert "v3/send" in url

    url, headers = config["contactslist_csvdata"]
    assert "v3/DATA/contactslist" in url
    assert headers["Content-Type"] == "text/plain"

    url, headers = config["contactslist_csverror"]
    assert "v3/DATA/contactslist" in url
    assert headers["Content-type"] == "application/json"


# --- Legacy Functionality Coverage Tests ---

def test_legacy_action_id_fallback(client_offline: Client) -> None:
    """Test backward compatibility of the action_id parameter alias."""
    assert (
        client_offline.contact._build_url(id=999)
        == "https://api.mailjet.com/v3/REST/contact/999"
    )


def test_prepare_url_headers_and_url() -> None:
    """Verify the legacy prepare_url regex callback mapping logic."""
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    name = re.sub(r"[A-Z]", prepare_url, "contactManagecontactslists")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"


def test_prepare_url_mixed_case_input() -> None:
    """Verify legacy URL mapping handling for mixed case."""
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "contact")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"


def test_prepare_url_empty_input() -> None:
    """Verify legacy URL mapping handling for empty strings."""
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"


def test_prepare_url_with_numbers_input_bad() -> None:
    """Verify legacy URL mapping correctly ignores internal numbers."""
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "contact1Managecontactslists1")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact1"


def test_prepare_url_leading_trailing_underscores_input_bad() -> None:
    """Verify legacy URL mapping handles pre-existing underscores."""
    config = Config()
    name = re.sub(r"[A-Z]", prepare_url, "_contactManagecontactslists_")
    url, _ = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"
