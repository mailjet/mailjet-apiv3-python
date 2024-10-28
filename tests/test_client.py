from __future__ import annotations

import json
import os
import re
from re import Match

import pytest

from mailjet_rest.utils.version import get_version
from mailjet_rest import Client
from mailjet_rest.client import prepare_url, Config, Endpoint


@pytest.fixture
def simple_data() -> tuple[dict[str, list[dict[str, str]]], str]:
    data: dict[str, list[dict[str, str]]] = {"Data": [{"Name": "first_name", "Value": "John"}]}
    data_encoding: str = "utf-8"
    return data, data_encoding

@pytest.fixture
def client_mj30() -> Client:
    auth: tuple[str, str] = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])
    return Client(auth=auth)

@pytest.fixture
def client_mj31() -> Client:
    auth: tuple[str, str] = (os.environ["MJ_APIKEY_PUBLIC"], os.environ["MJ_APIKEY_PRIVATE"])
    return Client(auth=auth, version="v3.1",)

def test_json_data_str_or_bytes_with_ensure_ascii(simple_data) -> None:
    data, data_encoding = simple_data
    ensure_ascii: bool = True

    if "application/json" and data is not None:
        json_data: str = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data: bytes = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)

def test_json_data_str_or_bytes_with_ensure_ascii_false(simple_data) -> None:
    data, data_encoding = simple_data
    ensure_ascii: bool = False

    if "application/json" and data is not None:
        json_data: str = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data: bytes = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)

def test_json_data_is_none(simple_data) -> None:
    data, data_encoding = simple_data
    ensure_ascii: bool = True
    data: dict | None = None

    if "application/json" and data is not None:
        json_data: str = json.dumps(data, ensure_ascii=ensure_ascii)

        assert isinstance(json_data, str)
        if not ensure_ascii:
            json_data: bytes = json_data.encode(data_encoding)
            assert isinstance(json_data, bytes)


def test_prepare_url_list_splitting() -> None:
    """Test prepare_url: list splitting"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    split: list[str] = name.split("_")
    assert split == ["contact", "managecontactslists"]

def test_prepare_url_first_list_element() -> None:
    """Test prepare_url: list splitting, the first element, url, and headers"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    split: list[str] = name.split("_")
    fname: str = split[0]
    assert fname == "contact"

def test_prepare_url_headers_and_url() -> None:
    """Test prepare_url: list splitting, the first element, url, and headers"""
    name: str = re.sub(r"[A-Z]", prepare_url, "contact_managecontactslists")
    config: Config = Config(version="v3", api_url="https://api.mailjet.com/")
    url, headers = config[name]
    assert url == "https://api.mailjet.com/v3/REST/contact"
    assert headers == {'Content-type': 'application/json', 'User-agent': f'mailjet-apiv3-python/v{get_version()}'}



# ======= TEST CLIENT ========

def test_post_with_no_param(client_mj30):
    result = client_mj30.sender.create(data={}).json()
    assert "StatusCode" in result and result["StatusCode"] == 400
