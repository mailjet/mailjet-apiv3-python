"""Property-based tests for synchronous Mailjet SDK Client invariants.

Powered by Hypothesis.
"""

from __future__ import annotations

import contextlib
from typing import Any
from unittest.mock import MagicMock, patch
import warnings

from hypothesis import example, given, settings, strategies as st

from mailjet_rest.client import Client, Endpoint


@settings(max_examples=300)
@given(auth_input=st.one_of(st.tuples(st.text(), st.text()), st.text(), st.integers(), st.none()))
@example(auth_input=("", "\r"))
@example(auth_input=("", "\xa0"))
def test_property_auth_coercion(auth_input: Any) -> None:
    """INVARIANT: Client must successfully auth or reject with clear Type/Value error."""
    with contextlib.suppress(ValueError, TypeError):
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            client = Client(auth=auth_input, version="v3")
        if isinstance(auth_input, tuple):
            assert client.auth == (auth_input[0].strip(), auth_input[1].strip())
        elif isinstance(auth_input, str):
            assert "Authorization" in client.session.headers


@settings(max_examples=300)
@given(route_name=st.text(min_size=1, max_size=20, alphabet=st.characters(blacklist_categories=("Cs", "Z"))))
def test_property_client_getattr_difflib(route_name: str) -> None:
    """INVARIANT: Random unmapped endpoints should hit fallback or be caught as difflib typos."""
    client = Client(auth=("a", "b"))
    try:
        endpoint = getattr(client, route_name)
        if isinstance(endpoint, Endpoint):
            assert endpoint.name == route_name
        else:
            # Built-in attributes (like 'session', 'auth', 'config') are valid client attributes
            return
    except AttributeError as e:
        # Check against both standard python attribute errors and custom difflib typo messages
        if route_name.startswith("_") or route_name in {"session", "config", "auth"}:
            assert "object has no attribute" in str(e) or "has no attribute" in str(e)
        else:
            assert "has no endpoint or attribute" in str(e)


@settings(max_examples=200)
@given(
    method=st.sampled_from(["GET", "POST", "PUT", "DELETE"]),
    payload=st.one_of(
        st.dictionaries(st.text(), st.text()), st.lists(st.dictionaries(st.text(), st.text())), st.none()
    ),
    # Cap the fuzzed timeout at the maximum allowed 86400 seconds limit (CWE-400)
    timeout=st.one_of(st.integers(min_value=1, max_value=86400), st.none()),
)
def test_property_api_call_resilience(method: Any, payload: Any, timeout: Any) -> None:
    """INVARIANT: api_call wrapper safely assigns kwargs, hashes mutations, and fires request."""
    client = Client(auth=("a", "b"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    with patch.object(Client, "_execute_request", return_value=mock_resp) as mock_exec:
        # API call must not crash on random standard payload variants
        res = client.api_call(
            method=method, url="https://api.mailjet.com/v3/test", headers={}, data=payload, timeout=timeout
        )
        assert res.status_code == 200

        # Ensure idempotency was calculated for valid dictionaries/lists during mutations
        if method in {"POST", "PUT", "DELETE"} and isinstance(payload, (dict, list)):
            call_args = mock_exec.call_args[1]
            assert "Idempotency-Key" in call_args["headers"]
