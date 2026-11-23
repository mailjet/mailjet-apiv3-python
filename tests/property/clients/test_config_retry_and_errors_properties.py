"""Property-based tests for Mailjet SDK Config, Retry backoff, Telemetry, and Error Mapping.

Powered by Hypothesis.
"""

from __future__ import annotations

import contextlib
import math
from typing import Any
from unittest.mock import MagicMock
import warnings

import pytest
from hypothesis import given, settings, strategies as st
from requests.exceptions import RequestException
from urllib3.util.retry import Retry

from mailjet_rest.client import Client, JitterRetry
from mailjet_rest.config import Config
from mailjet_rest.errors import (
    ApiError,
    ApiRateLimitError,
    DoesNotExistError,
    MailjetAuthError,
    ValidationError,
)


# ==========================================
# 1. Config & Type Confusion Invariants
# ==========================================
@settings(max_examples=500)
@given(
    timeout_val=st.one_of(
        st.integers(),
        st.floats(allow_nan=True, allow_infinity=True),
        st.text(),
        st.binary(),
        st.lists(st.integers()),
        st.tuples(st.floats(allow_nan=True), st.floats()),
        st.none(),
    )
)
def test_property_config_timeout_coercion(timeout_val: Any) -> None:
    """INVARIANT: Config must successfully coerce the timeout into a valid,
    positive float/int (or tuple), leave it as None, or explicitly raise
    a ValueError/TypeError. It must never silently leak bad types.
    """
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        with contextlib.suppress(ValueError, TypeError):
            config = Config(api_url="https://api.mailjet.com/", timeout=timeout_val)

            if config.timeout is None:
                assert True
            elif isinstance(config.timeout, tuple):
                assert len(config.timeout) == 2
                for t in config.timeout:
                    assert isinstance(t, (float, int))
                    if isinstance(t, float):
                        assert not math.isnan(t)
                        assert not math.isinf(t)
                    assert t > 0
            else:
                assert isinstance(config.timeout, (float, int))
                if isinstance(config.timeout, float):
                    assert not math.isnan(config.timeout)
                    assert not math.isinf(config.timeout)
                assert config.timeout > 0


# ==========================================
# 2. Telemetry & Retry Backoff Invariants
# ==========================================
@pytest.mark.property_heavy
@settings(max_examples=500)
@given(
    payload=st.recursive(
        st.dictionaries(st.text(), st.text()),
        lambda children: st.lists(children) | st.dictionaries(st.text(), children),
        max_leaves=25,
    )
)
def test_property_telemetry_extraction_resilience(payload: Any) -> None:
    """INVARIANT: Telemetry extractor must gracefully handle chaotic payloads."""
    trace_suffix, structured_data = Client._extract_telemetry(payload, None)
    assert isinstance(trace_suffix, str)
    assert isinstance(structured_data, dict)


@settings(max_examples=500)
@given(consecutive_errors=st.integers(min_value=1, max_value=10))
def test_property_jitter_backoff_bounds(consecutive_errors: int) -> None:
    """INVARIANT: JitterRetry must return wait time between 0 and standard exponential limit."""
    retry: Retry = JitterRetry(total=10, backoff_factor=1)
    for _ in range(consecutive_errors):
        retry = retry.increment(error=Exception("Simulated Drop"))
    standard_backoff = retry.backoff_factor * (2 ** (len(retry.history) - 1))
    assert 0 <= retry.get_backoff_time() <= standard_backoff


# ==========================================
# 3. Exception Mapping Hierarchy Invariants
# ==========================================
@settings(max_examples=300)
@given(status_code=st.integers(min_value=400, max_value=599), body_text=st.text())
def test_property_api_error_mapping(status_code: int, body_text: str) -> None:
    """INVARIANT: The Client must intercept all requests.RequestException instances
    and map them perfectly to the Mailjet domain-specific exception hierarchy
    based on the HTTP status code.
    """
    mock_response = MagicMock()
    mock_response.status_code = status_code
    mock_response.text = body_text

    original_exc = RequestException("Simulated Network Error", response=mock_response)

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

    with pytest.raises(expected_exc) as exc_info:
        Client._handle_api_error(original_exc)

    if expected_exc != ApiError:
        assert exc_info.value.status_code == status_code
        assert exc_info.value.response_body == body_text


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
