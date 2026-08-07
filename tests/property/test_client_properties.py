"""Property-based tests for Mailjet SDK Client logic and Telemetry.
Powered by Hypothesis.
"""

from typing import Any
from unittest.mock import MagicMock

from hypothesis import given, settings, strategies as st

from mailjet_rest.client import Client, JitterRetry


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


@settings(max_examples=300)
@given(auth_input=st.one_of(st.tuples(st.text(), st.text()), st.text(), st.integers(), st.none()))
def test_property_auth_coercion(auth_input: Any) -> None:
    """INVARIANT: Client must successfully auth or reject with clear Type/Value error."""
    try:
        client = Client(auth=auth_input, version="v3")
        if isinstance(auth_input, tuple):
            assert client.auth == auth_input
        elif isinstance(auth_input, str):
            assert "Authorization" in client.session.headers
    except (ValueError, TypeError):
        pass


@settings(max_examples=500)
@given(consecutive_errors=st.integers(min_value=1, max_value=10))
def test_property_jitter_backoff_bounds(consecutive_errors: int) -> None:
    """INVARIANT: JitterRetry must return wait time between 0 and standard exponential limit."""
    retry = JitterRetry(total=10, backoff_factor=1)
    for _ in range(consecutive_errors):
        retry = retry.increment(error=Exception("Simulated Drop"))
    standard_backoff = retry.backoff_factor * (2 ** (len(retry.history) - 1))
    assert 0 <= retry.get_backoff_time() <= standard_backoff


@settings(max_examples=300)
@given(route_name=st.text(min_size=1, max_size=20, alphabet=st.characters(blacklist_categories=("Cs", "Z"))))
def test_property_client_getattr_difflib(route_name: str) -> None:
    """INVARIANT: Random unmapped endpoints should hit fallback or be caught as difflib typos."""
    client = Client(auth=("a", "b"))
    try:
        endpoint = getattr(client, route_name)
        assert endpoint.name == route_name
    except AttributeError as e:
        # Check against both standard python attribute errors and custom difflib typo messages
        if route_name.startswith("_"):
            assert "object has no attribute" in str(e)
        else:
            assert "has no endpoint or attribute" in str(e)


@settings(max_examples=200)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    payload=st.one_of(
        st.dictionaries(st.text(), st.text()), st.lists(st.dictionaries(st.text(), st.text())), st.none()
    ),
    timeout=st.one_of(st.integers(min_value=1), st.none()),
)
def test_property_api_call_resilience(method: Any, payload: Any, timeout: Any) -> None:
    """INVARIANT: api_call wrapper safely assigns kwargs, hashes mutations, and fires request."""
    client = Client(auth=("a", "b"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    client._execute_request = MagicMock(return_value=mock_resp)  # type: ignore[method-assign]

    # API call must not crash on random standard payload variants
    res = client.api_call(
        method=method, url="https://api.mailjet.com/v3/test", headers={}, data=payload, timeout=timeout
    )
    assert res.status_code == 200

    # Ensure idempotency was calculated for valid dictionaries/lists during mutations
    if method in {"POST", "PUT", "DELETE"} and isinstance(payload, (dict, list)):
        call_args = client._execute_request.call_args[1]
        assert "Idempotency-Key" in call_args["headers"]
