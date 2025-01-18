from __future__ import annotations
from functools import partial

import glob
import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Any

import pytest
from _pytest.logging import LogCaptureFixture

from mailjet_rest.utils.version import get_version
from mailjet_rest import Client
from mailjet_rest.client import prepare_url, parse_response, logging_handler, Config


def debug_entries() -> tuple[str, str, str, str, str, str, str]:
    """Provide a simple tuples with debug entries for testing purposes.

    Parameters:
    None

    Returns:
    tuple: A tuple containing seven debug entries
    """
    entries = (
        "DEBUG",
        "REQUEST:",
        "REQUEST_HEADERS:",
        "REQUEST_CONTENT:",
        "RESPONSE:",
        "RESP_HEADERS:",
        "RESP_CODE:",
    )
    return entries


def validate_datetime_format(date_text: str, datetime_format: str) -> None:
    """Validate the format of a given date string against a specified datetime format.

    Parameters:
    date_text (str): The date string to be validated.
    datetime_format (str): The datetime format to which the date string should be validated.

    Raises:
    ValueError: If the date string does not match the specified datetime format.
    """
    try:
        datetime.strptime(date_text, datetime_format)
    except ValueError:
        raise ValueError("Incorrect data format, should be %Y%m%d_%H%M%S")


@pytest.fixture
def simple_data() -> tuple[dict[str, list[dict[str, str]]], str]:
    """Provide a simple data structure and its encoding for testing purposes.

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
    """Create and return a Mailjet API client instance for version 3.0.

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
    """Create and return a Mailjet API client instance for version 3.0, but with invalid authentication credentials.

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
    """Create and return a Mailjet API client instance for version 3.1.

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
    """This function tests the conversion of structured data into JSON format with the specified encoding settings.

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


def test_debug_logging_to_stdout_has_all_debug_entries(
    client_mj30: Client,
    caplog: LogCaptureFixture,
) -> None:
    """This function tests the debug logging to stdout, ensuring that all debug entries are present.

    Parameters:
    client_mj30 (Client): An instance of the Mailjet API client.
    caplog (LogCaptureFixture): A fixture for capturing log entries.
    """
    result = client_mj30.contact.get()
    parse_response(result, lambda: logging_handler(to_file=False), debug=True)

    assert result.status_code == 200
    assert len(caplog.records) == 6
    assert all(x in caplog.text for x in debug_entries())


def test_debug_logging_to_stdout_has_all_debug_entries_when_unknown_or_not_found(
    client_mj30: Client,
    caplog: LogCaptureFixture,
) -> None:
    """This function tests the debug logging to stdout, ensuring that all debug entries are present.

    Parameters:
    client_mj30 (Client): An instance of the Mailjet API client.
    caplog (LogCaptureFixture): A fixture for capturing log entries.
    """
    # A wrong "cntact" endpoint to get 400 "Unknown resource" error message
    result = client_mj30.cntact.get()
    parse_response(result, lambda: logging_handler(to_file=False), debug=True)

    assert 400 <= result.status_code <= 404
    assert len(caplog.records) == 8
    assert all(x in caplog.text for x in debug_entries())


def test_debug_logging_to_stdout_when_retrieve_message_with_id_type_mismatch(
    client_mj30: Client,
    caplog: LogCaptureFixture,
) -> None:
    """This function tests the debug logging to stdout by retrieving message if id type mismatch, ensuring that all debug entries are present.

    GET https://api.mailjet.com/v3/REST/message/$MESSAGE_ID

    Parameters:
    client_mj30 (Client): An instance of the Mailjet API client.
    caplog (LogCaptureFixture): A fixture for capturing log entries.
    """
    _id = "*************"  # $MESSAGE_ID with all "*" will cause "Incorrect ID provided - ID type mismatch" (Error 400).
    result = client_mj30.message.get(_id)
    parse_response(result, lambda: logging_handler(to_file=False), debug=True)

    assert result.status_code == 400
    assert len(caplog.records) == 8
    assert all(x in caplog.text for x in debug_entries())


def test_debug_logging_to_stdout_when_retrieve_message_with_object_not_found(
    client_mj30: Client,
    caplog: LogCaptureFixture,
) -> None:
    """This function tests the debug logging to stdout by retrieving message if object not found, ensuring that all debug entries are present.

    GET https://api.mailjet.com/v3/REST/message/$MESSAGE_ID

    Parameters:
    client_mj30 (Client): An instance of the Mailjet API client.
    caplog (LogCaptureFixture): A fixture for capturing log entries.
    """
    _id = "0000000000000"  # $MESSAGE_ID with all zeros "0" will cause "Object not found" (Error 404).
    result = client_mj30.message.get(_id)
    parse_response(result, lambda: logging_handler(to_file=False), debug=True)

    assert result.status_code == 404
    assert len(caplog.records) == 8
    assert all(x in caplog.text for x in debug_entries())


def test_debug_logging_to_log_file(
    client_mj30: Client, caplog: LogCaptureFixture
) -> None:
    """This function tests the debug logging to a log file.

    It sends a GET request to the 'contact' endpoint of the Mailjet API client, parses the response,
    logs the debug information to a log file, validates that the log filename has the correct datetime format provided,
    and then verifies the existence and removal of the log file.

    Parameters:
    client_mj30 (Client): An instance of the Mailjet API client.
    caplog (LogCaptureFixture): A fixture for capturing log entries.
    """
    result = client_mj30.contact.get()
    parse_response(result, logging_handler, debug=True)
    partial(logging_handler, to_file=True)
    cwd = Path.cwd()
    log_files = glob.glob("*.log")
    for log_file in log_files:
        log_file_name = Path(log_file).stem
        validate_datetime_format(log_file_name, "%Y%m%d_%H%M%S")
        log_file_path = os.path.join(cwd, log_file)

        assert result.status_code == 200
        assert Path(log_file_path).exists()

        print(f"Removing log file {log_file}...")
        Path(log_file_path).unlink()
        print(f"The log file {log_file} has been removed.")
