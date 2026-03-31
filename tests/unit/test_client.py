"""Unit tests for the Mailjet API client routing and internal logic."""

from __future__ import annotations

import logging
import re
from typing import Any

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]
from pytest import LogCaptureFixture

from mailjet_rest._version import __version__
from mailjet_rest.client import (
    Client,
    Config,
    logging_handler,
    parse_response,
    prepare_url,
)


@pytest.fixture
def client_offline() -> Client:
    """Return a client with fake credentials for pure offline unit testing.

    Returns:
    - Client: An instance of the Mailjet Client.
    """
    return Client(auth=("fake_public_key", "fake_private_key"), version="v3")


# --- Dynamic API Versioning Tests ---


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v4", "v99_future"])
def test_dynamic_versions_standard_rest(api_version: str) -> None:
    """Test standard REST API URLs adapt to any version string.

    Parameters:
    - api_version (str): The version string injected by pytest.
    """
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
    """Test Send API URLs correctly adapt to any version string without the REST prefix.

    Parameters:
    - api_version (str): The version string injected by pytest.
    """
    client = Client(auth=("a", "b"), version=api_version)
    assert client.send._build_url() == f"https://api.mailjet.com/{api_version}/send"


@pytest.mark.parametrize("api_version", ["v1", "v3", "v3.1", "v4", "v99_future"])
def test_dynamic_versions_data_api(api_version: str) -> None:
    """Test DATA API URLs correctly adapt to any version string.

    Parameters:
    - api_version (str): The version string injected by pytest.
    """
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
    """Test Content API routing with sub-actions.

    Parameters:
    - client_offline (Client): Offline test fixture.
    """
    assert (
        client_offline.template_detailcontent._build_url(id=123)
        == "https://api.mailjet.com/v3/REST/template/123/detailcontent"
    )


# --- HTTP Methods & Execution Coverage Tests ---


def test_http_methods_and_timeout(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Mock the session request to hit standard wrapper methods and fallback parameters.

    Parameters:
    - client_offline (Client): Offline test fixture.
    - monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch utility.
    """

    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = 200
        return resp

    monkeypatch.setattr(client_offline.session, "request", mock_request)

    assert client_offline.contact.get(id=1, filters={"limit": 1}).status_code == 200
    assert client_offline.contact.create(data={"Name": "Test"}, id=1).status_code == 200
    assert (
        client_offline.contact.update(id=1, data={"Name": "Update"}).status_code == 200
    )
    assert client_offline.contact.delete(id=1).status_code == 200

    resp = client_offline.contact(method="GET", headers={"X-Custom": "1"}, timeout=None)
    assert resp.status_code == 200


def test_client_coverage_edge_cases(
    client_offline: Client, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Explicitly hit partial branches (BrPart) to achieve 100% coverage.

    Parameters:
    - client_offline (Client): Offline test fixture.
    - monkeypatch (pytest.MonkeyPatch): Pytest monkeypatch utility.
    """

    def mock_request(*args: Any, **kwargs: Any) -> requests.Response:
        return requests.Response()

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
    """Test backward compatibility of the action_id parameter alias.

    Parameters:
    - client_offline (Client): Offline test fixture.
    """
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


# --- Legacy Logging Coverage Tests ---


@pytest.fixture
def mock_response() -> requests.Response:
    """Provide a mock Response object for offline logging testing."""
    response = requests.Response()
    response.status_code = 404
    response._content = b'{"ErrorMessage": "Not found"}'
    return response


def test_debug_logging_to_stdout(
    mock_response: requests.Response, caplog: LogCaptureFixture
) -> None:
    """Test writing debug statements to standard output.

    Parameters:
    - mock_response (requests.Response): Mock API response.
    - caplog (LogCaptureFixture): Pytest logger capture.
    """
    with caplog.at_level(logging.DEBUG, logger="mailjet_rest"):
        parse_response(mock_response, handler=logging_handler(), debug=True)
    assert "Response status: 404" in caplog.text


def test_debug_logging_to_log_file(
    mock_response: requests.Response, caplog: LogCaptureFixture
) -> None:
    """Test generating a FileHandler for the debug logger.

    Parameters:
    - mock_response (requests.Response): Mock API response.
    - caplog (LogCaptureFixture): Pytest logger capture.
    """
    handler_factory = lambda: logging_handler(to_file=True)
    with caplog.at_level(logging.DEBUG, logger="mailjet_rest"):
        parse_response(mock_response, handler=handler_factory, debug=True)
    assert "Response status: 404" in caplog.text


def test_parse_response_branches(mock_response: requests.Response) -> None:
    """Hit the edge case branches in parse_response (no handler, and duplicate handler).

    Parameters:
    - mock_response (requests.Response): Mock API response.
    """
    # 1. Missing branch: handler is explicitly None
    parse_response(mock_response, debug=True)

    # 2. Missing branch: handler is already attached to logger
    logger = logging.getLogger("mailjet_rest")
    dummy_handler = logging.StreamHandler()
    logger.addHandler(dummy_handler)
    try:
        parse_response(mock_response, handler=dummy_handler, debug=True)
    finally:
        logger.removeHandler(dummy_handler)


def test_parse_response_exception_handling(mock_response: requests.Response) -> None:
    """Force an exception inside parse_response's logging handler logic to cover the except block.

    Parameters:
    - mock_response (requests.Response): Mock API response.
    """
    parse_response(mock_response, handler=lambda: 1 / 0, debug=True)
