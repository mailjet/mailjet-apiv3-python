"""Tests explicitly covering the restored legacy components to maintain 100% branch coverage."""

from __future__ import annotations

import warnings
from typing import Any

import pytest
import requests  # pyright: ignore[reportMissingModuleSource]

from mailjet_rest.client import (
    ActionDeniedError,
    ApiRateLimitError,
    AuthorizationError,
    Client,
    DoesNotExistError,
    ValidationError,
    logging_handler,
    parse_response,
)


def test_legacy_exceptions_exist_and_inherit_properly() -> None:
    """Verify that all deprecated exceptions were restored and inherit from Exception."""
    for error_class in [
        AuthorizationError,
        ActionDeniedError,
        DoesNotExistError,
        ValidationError,
        ApiRateLimitError,
    ]:
        assert issubclass(error_class, Exception)
        # Even though they aren't actively raised by the SDK anymore,
        # checking initialization ensures users' try/except blocks won't crash.
        instance = error_class("Legacy Error")
        assert str(instance) == "Legacy Error"


def test_parse_response_emits_deprecation_warning() -> None:
    """Verify parse_response gracefully falls back to JSON/Text while warning the developer."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b'{"success": true}'

    with pytest.warns(DeprecationWarning, match="parse_response is deprecated"):
        result = parse_response(resp)
        assert isinstance(result, dict)
        assert result.get("success") is True


def test_parse_response_handles_value_error_fallback() -> None:
    """Verify parse_response returns raw text if JSON decoding fails."""
    resp = requests.Response()
    resp.status_code = 200
    resp._content = b"Plain text response"

    # Catching the warning to keep the test output clean
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        result = parse_response(resp)
        assert result == "Plain text response"


def test_logging_handler_emits_deprecation_warning() -> None:
    """Verify logging_handler executes safely but warns the developer."""
    resp = requests.Response()

    with pytest.warns(DeprecationWarning, match="logging_handler is deprecated"):
        logging_handler(resp)


def test_legacy_kwargs_emit_deprecation_warning(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify that using ensure_ascii or data_encoding in Client.create emits a warning."""
    client = Client(auth=("a", "b"), version="v3")

    def mock_request(method: str, url: str, data: Any = None, **kwargs: Any) -> requests.Response:
        assert "ensure_ascii" not in kwargs  # Should be consumed by the wrapper
        assert data is not None
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
