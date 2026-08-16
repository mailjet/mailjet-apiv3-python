"""Property-based tests for Mailjet SDK Error Handling and Mapping.
Powered by Hypothesis.
"""

from unittest.mock import MagicMock

import pytest
from hypothesis import given, settings, strategies as st
from requests.exceptions import RequestException

from mailjet_rest.client import Client
from mailjet_rest.errors import (
    ApiError,
    ApiRateLimitError,
    DoesNotExistError,
    MailjetAuthError,
    ValidationError,
)


# ==========================================
# 1. Exception Mapping Hierarchy Invariants
# ==========================================
@settings(max_examples=300)
@given(status_code=st.integers(min_value=400, max_value=599), body_text=st.text())
def test_property_api_error_mapping(status_code: int, body_text: str) -> None:
    """INVARIANT: The Client must intercept all requests.RequestException instances
    and map them perfectly to the Mailjet domain-specific exception hierarchy
    based on the HTTP status code.
    """
    # Create a mock requests exception
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = body_text

    original_exc = RequestException("Simulated Network Error", response=mock_response)

    # Determine the mathematically expected Exception type
    expected_exc: type[ApiError]
    if status_code in (401, 403):
        expected_exc = MailjetAuthError
    elif status_code == 429:
        expected_exc = ApiRateLimitError
    elif status_code == 404:
        expected_exc = DoesNotExistError
    elif status_code == 400:
        expected_exc = ValidationError
    else:
        expected_exc = ApiError

    # Assert that the Client strictly upholds the mapping contract
    with pytest.raises(expected_exc) as exc_info:
        Client._handle_api_error(original_exc)

    # If it is a mapped subclass of MailjetApiError, assert body retention
    if expected_exc != ApiError:
        assert exc_info.value.status_code == status_code
        assert exc_info.value.response_body == body_text


# ==========================================
# 2. Null Response Exception Invariants
# ==========================================
@settings(max_examples=100)
@given(error_msg=st.text())
def test_property_null_response_error_handling(error_msg: str) -> None:
    """INVARIANT: If a RequestException occurs without a response object attached
    (e.g., DNS failure, connection reset), the mapper must safely fall back
    to the base ApiError without raising an AttributeError.
    """
    original_exc = RequestException(error_msg, response=None)

    with pytest.raises(ApiError) as exc_info:
        Client._handle_api_error(original_exc)

    assert error_msg in str(exc_info.value)
