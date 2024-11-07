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
    """This function tests the prepare_url function by splitting a string containing underscores and converting the first letter of each word to uppercase.

    The function then compares the resulting list with an expected list.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It splits the resulting string into a list using the underscore as the delimiter.
    - It asserts that the resulting list is equal to the expected list ["contact", "managecontactslists"].
    """
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    split: list[str] = name.split("_")  # noqa: FURB184
    assert split == ["contact", "managecontactslists"]


def test_prepare_url_first_list_element() -> None:
    """This function tests the prepare_url function by splitting a string containing underscores, and retrieving the first element of the resulting list.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It splits the resulting string into a list using the underscore as the delimiter.
    - It asserts that the first element of the split list is equal to "contact".
    """
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    fname: str = name.split("_")[0]
    assert fname == "contact"


def test_prepare_url_headers_and_url() -> None:
    """Test the prepare_url function by splitting a string containing underscores, and retrieving the first element of the resulting list.

    Additionally, this test verifies the URL and headers generated by the prepare_url function.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is equal to "https://api.mailjet.com/v3/REST/contact" and that the headers match the expected headers.
    """
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
    """Tests a POST request with an empty data payload.

    This test sends a POST request to the 'create' endpoint using an empty dictionary
    as the data payload. It checks that the API responds with a 400 status code,
    indicating a bad request due to missing required parameters.

    Parameters:
        client_mj30 (Client): An instance of the Mailjet API client.

    Raises:
        AssertionError: If "StatusCode" is not in the result or if its value
        is not 400.
    """
    result = client_mj30.sender.create(data={}).json()
    assert "StatusCode" in result and result["StatusCode"] == 400


def test_get_no_param(client_mj30: Client) -> None:
    """Tests a GET request to retrieve contact data without any parameters.

    This test sends a GET request to the 'contact' endpoint without filters or
    additional parameters. It verifies that the response includes both "Data"
    and "Count" fields, confirming the endpoint returns a valid structure.

    Parameters:
        client_mj30 (Client): An instance of the Mailjet API client.

    Raises:
        AssertionError: If "Data" or "Count" are not present in the response.
    """
    result: Any = client_mj30.contact.get().json()
    assert "Data" in result and "Count" in result


def test_client_initialization_with_invalid_api_key(
    client_mj30_invalid_auth: Client,
) -> None:
    """This function tests the initialization of a Mailjet API client with invalid authentication credentials.

    Parameters:
    client_mj30_invalid_auth (Client): An instance of the Mailjet API client configured for version 3.0.
                                       The client is authenticated using invalid public and private API keys.

    Returns:
    None: The function does not return any value. It is expected to raise a ValueError when the client is used to make requests.

    Note:
    - The function uses the pytest.raises context manager to assert that a ValueError is raised when the client's contact.get() method is called.
    """
    with pytest.raises(ValueError):
        client_mj30_invalid_auth.contact.get().json()


def test_prepare_url_mixed_case_input() -> None:
    """Test prepare_url function with mixed case input.

    This function tests the prepare_url function by providing a string with mixed case characters.
    It then compares the resulting URL with the expected URL.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is equal to the expected URL and that the headers match the expected headers.
    """
    name: str = re.sub(r"[A-Z]", prepare_url, "contact")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_empty_input() -> None:
    """Test prepare_url function with empty input.

    This function tests the prepare_url function by providing an empty string as input.
    It then compares the resulting URL with the expected URL.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is equal to the expected URL and that the headers match the expected headers.
    """
    name = re.sub(r"[A-Z]", prepare_url, "")
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_with_numbers_input_bad() -> None:
    """Test the prepare_url function with input containing numbers.

    This function tests the prepare_url function by providing a string with numbers.
    It then compares the resulting URL with the expected URL.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is not equal to the expected URL and that the headers match the expected headers.
    """
    name = re.sub(r"[A-Z]", prepare_url, "contact1_managecontactslists1")
    config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_leading_trailing_underscores_input_bad() -> None:
    """Test prepare_url function with input containing leading and trailing underscores.

    This function tests the prepare_url function by providing a string with leading and trailing underscores.
    It then compares the resulting URL with the expected URL.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is not equal to the expected URL and that the headers match the expected headers.
    """
    name: str = re.sub(r"[A-Z]", prepare_url, "_contact_managecontactslists_")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }


def test_prepare_url_mixed_case_input_bad() -> None:
    """Test prepare_url function with mixed case input.

    This function tests the prepare_url function by providing a string with mixed case characters.
    It then compares the resulting URL with the expected URL.

    Parameters:
    None

    Note:
    - The function uses the re.sub method to replace uppercase letters with the prepare_url function.
    - It creates a Config object with the specified version and API URL.
    - It retrieves the URL and headers from the Config object using the modified string as the key.
    - It asserts that the URL is not equal to the expected URL and that the headers match the expected headers.
    """
    name: str = re.sub(r"[A-Z]", prepare_url, "cOntact")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url != "https://api.mailjet.com/v3/REST/contact"
    assert headers == {
        "Content-type": "application/json",
        "User-agent": f"mailjet-apiv3-python/v{get_version()}",
    }
