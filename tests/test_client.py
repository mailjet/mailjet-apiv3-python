from __future__ import annotations

import json
import os
import re
from typing import Any

import pytest

from mailjet_rest.utils.version import get_version
from mailjet_rest import Client
from mailjet_rest.client import prepare_url, Config


@pytest.fixture
def simple_data() -> tuple[dict[str, list[dict[str, str]]], str]:
    """
    This function provides a simple data structure and its encoding for testing purposes.

    Parameters:
    None

    Returns:
    tuple: A tuple containing two elements:
        - A dictionary representing structured data with a list of dictionaries.
        - A string representing the encoding of the data.
    """
    data: dict[str, list[dict[str, str]]] = {
        "Data": [{"Name": "first_name", "Value": "John"}]
    }
    data_encoding: str = "utf-8"
    return data, data_encoding


@pytest.fixture
def client_mj30() -> Client:
    """
    This function creates and returns a Mailjet API client instance for version 3.0.

    Parameters:
    None

    Returns:
    Client: An instance of the Mailjet API client configured for version 3.0. The client is authenticated using the public and private API keys provided as environment variables.
    """
    auth: tuple[str, str] = (
        os.environ["MJ_APIKEY_PUBLIC"],
        os.environ["MJ_APIKEY_PRIVATE"],
    )
    return Client(auth=auth)


@pytest.fixture
def client_mj30_invalid_auth() -> Client:
    """
    This function creates and returns a Mailjet API client instance for version 3.0,
    but with invalid authentication credentials.

    Parameters:
    None

    Returns:
    Client: An instance of the Mailjet API client configured for version 3.0.
           The client is authenticated using invalid public and private API keys.
           If the client is used to make requests, it will raise a ValueError.
    """
    auth: tuple[str, str] = (
        "invalid_public_key",
        "invalid_private_key",
    )
    return Client(auth=auth)


@pytest.fixture
def client_mj31() -> Client:
    """
    This function creates and returns a Mailjet API client instance for version 3.1.

    Parameters:
    None

    Returns:
    Client: An instance of the Mailjet API client configured for version 3.1.
           The client is authenticated using the public and private API keys provided as environment variables.

    Note:
    - The function retrieves the public and private API keys from the environment variables 'MJ_APIKEY_PUBLIC' and 'MJ_APIKEY_PRIVATE' respectively.
    - The client is initialized with the provided authentication credentials and the version set to 'v3.1'.
    """
    auth: tuple[str, str] = (
        os.environ["MJ_APIKEY_PUBLIC"],
        os.environ["MJ_APIKEY_PRIVATE"],
    )
    return Client(
        auth=auth,
        version="v3.1",
    )


def test_json_data_str_or_bytes_with_ensure_ascii(
    simple_data: tuple[dict[str, list[dict[str, str]]], str]
) -> None:
    """
    This function tests the conversion of structured data into JSON format with the specified encoding settings.

    Parameters:
    simple_data (tuple[dict[str, list[dict[str, str]]], str]): A tuple containing two elements:
        - A dictionary representing structured data with a list of dictionaries.
        - A string representing the encoding of the data.

    Returns:
    None: The function does not return any value. It performs assertions to validate the JSON conversion.
    """
    data, data_encoding = simple_data
    ensure_ascii: bool = True

    if "application/json" and data is not None:
        json_data: str | bytes | None = None
        json_data = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)


def test_json_data_str_or_bytes_with_ensure_ascii_false(
    simple_data: tuple[dict[str, list[dict[str, str]]], str]
) -> None:
    """
    This function tests the conversion of structured data into JSON format with the specified encoding settings.
    It specifically tests the case where the 'ensure_ascii' parameter is set to False.

    Parameters:
    simple_data (tuple[dict[str, list[dict[str, str]]], str]): A tuple containing two elements:
        - A dictionary representing structured data with a list of dictionaries.
        - A string representing the encoding of the data.

    Returns:
    None: The function does not return any value. It performs assertions to validate the JSON conversion.
    """
    data, data_encoding = simple_data
    ensure_ascii: bool = False

    if "application/json" and data is not None:
        json_data: str | bytes | None = None
        json_data = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)


def test_json_data_is_none(
    simple_data: tuple[dict[str, list[dict[str, str]]], str]
) -> None:
    """
    This function tests the conversion of structured data into JSON format when the data is None.

    Parameters:
    simple_data (tuple[dict[str, list[dict[str, str]]], str]): A tuple containing two elements:
        - A dictionary representing structured data with a list of dictionaries.
        - A string representing the encoding of the data.

    Returns:
    None: The function does not return any value. It performs assertions to validate the JSON conversion.
    """
    data, data_encoding = simple_data
    ensure_ascii: bool = True
    data: dict[str, list[dict[str, str]]] | None = None  # type: ignore

    if "application/json" and data is not None:
        json_data: str | bytes | None = None
        json_data = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)


def test_prepare_url_list_splitting() -> None:
    """Test prepare_url: list splitting"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    split: list[str] = name.split("_")  # noqa: FURB184
    assert split == ["contact", "managecontactslists"]


def test_prepare_url_first_list_element() -> None:
    """Test prepare_url: list splitting, the first element, url, and headers"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    fname: str = name.split("_")[0]
    assert fname == "contact"


def test_prepare_url_headers_and_url() -> None:
    """Test prepare_url: list splitting, the first element, url, and headers"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


# ======= TEST CLIENT ========


def test_post_with_no_param(client_mj30: Client) -> None:
    result = client_mj30.sender.create(data={}).json()
    assert "StatusCode" in result and result["StatusCode"] == 400


def test_get_no_param(client_mj30: Client) -> None:
    result: Any = client_mj30.contact.get().json()
    assert "Data" in result and "Count" in result


def test_client_initialization_with_invalid_api_key(
    client_mj30_invalid_auth: Client,
) -> None:
    with pytest.raises(ValueError):
        client_mj30_invalid_auth.contact.get().json()


def test_prepare_url_mixed_case_input() -> None:
    """Test prepare_url with mixed case input"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_empty_input() -> None:
    """Test prepare_url with empty input"""
    name = re.sub(r"[A-Z]", prepare_url, "")
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_with_numbers_input_bad() -> None:
    """Test prepare_url with input containing numbers"""
    name = re.sub(r"[A-Z]", prepare_url, "contact1_managecontactslists1")
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_leading_trailing_underscores_input_bad() -> None:
    """Test prepare_url with input containing leading and trailing underscores"""
    name: str = re.sub(r"[A-Z]", prepare_url, "_contact_managecontactslists_")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_mixed_case_input_bad() -> None:
    """Test prepare_url with mixed case input"""
    name: str = re.sub(r"[A-Z]", prepare_url, "cOntact")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }
