"""Property-based tests for Mailjet SDK URL Routing, Traversal Guards, and Sanitization.

Powered by Hypothesis.
"""

from __future__ import annotations

import contextlib
from typing import Any, Literal
from urllib.parse import urlparse
import warnings

from hypothesis import given, settings, strategies as st

from mailjet_rest.client import Client
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.utils.guardrails import SecurityGuard


_SURROGATE_BLACKLIST: tuple[Literal["Cs"]] = ("Cs",)


@settings(max_examples=500)
@given(segment=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False), st.none()))
def test_property_segment_sanitization(segment: Any) -> None:
    """INVARIANT: The segment sanitizer must mathematically guarantee the absence of traversal vectors."""
    with contextlib.suppress(ValueError, TypeError):
        clean_segment = SecurityGuard.sanitize_segment(segment)
        assert isinstance(clean_segment, str)
        assert "." not in clean_segment
        assert "\n" not in clean_segment
        assert "\r" not in clean_segment
        if segment is None:
            assert clean_segment == ""


@settings(max_examples=400)
@given(
    endpoint_name=st.text(min_size=1, alphabet=st.characters(blacklist_categories=_SURROGATE_BLACKLIST)),
    id_val=st.one_of(
        st.integers(), st.text(alphabet=st.characters(blacklist_categories=_SURROGATE_BLACKLIST)), st.none()
    ),
    action_id=st.one_of(
        st.integers(), st.text(alphabet=st.characters(blacklist_categories=_SURROGATE_BLACKLIST)), st.none()
    ),
)
def test_property_endpoint_build_url_resilience(endpoint_name: str, id_val: Any, action_id: Any) -> None:
    """INVARIANT: _build_url must securely map any random inputs to a safe URL without internal exceptions."""
    client = Client(auth=("a", "b"))
    endpoint = Endpoint(client=client, name=endpoint_name)

    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            url = endpoint._build_url(id_val=id_val, action_id=action_id)
        parsed_url = urlparse(url)
        assert parsed_url.scheme == "https"
        assert parsed_url.netloc == "api.mailjet.com"
        assert parsed_url.path.startswith("/")

        # Verify Headers are generated successfully
        headers = endpoint._build_headers()
        assert isinstance(headers, dict)
    except ValueError:
        # ValueErrors from missing required URI params (e.g. {id} format templates) or Traversal protections are safe
        pass


@settings(max_examples=500)
@given(route_name=st.text(min_size=3, max_size=15, alphabet=st.characters(blacklist_categories=("Cs", "Z"))))
def test_property_difflib_dynamic_routing_resilience(route_name: str) -> None:
    """INVARIANT: Random strings that are not >80% similar to existing endpoints
    must successfully fallback to dynamic Endpoint creation without raising
    a difflib typo AttributeError.
    """
    client = Client(auth=("test", "test"), version="v3")

    try:
        # We rename 'endpoint' to 'attr' since it might be a native class property
        attr = getattr(client, route_name)

        # Only assert .name if the returned attribute is actually an Endpoint
        if isinstance(attr, Endpoint):
            assert attr.name == route_name

    except AttributeError as e:
        if route_name.startswith("_"):
            assert "object has no attribute" in str(e)
        else:
            assert "has no endpoint or attribute" in str(e)


@settings(max_examples=500)
@given(
    id_val=st.text(),
    action_id=st.text(alphabet=st.characters(blacklist_categories=_SURROGATE_BLACKLIST)),
)
def test_property_url_traversal_prevention(id_val: Any, action_id: Any) -> None:
    r"""INVARIANT: No matter what malicious string is passed as an ID or Action,
    the resulting URL must never contain unencoded directory traversals.
    """
    with contextlib.suppress(ValueError):
        client = Client(auth=("test", "test"), version="v3")
        endpoint = Endpoint(name="contact", client=client)

        url = endpoint._build_url(id_val=id_val, action_id=action_id)

        base_len = len("https://api.mailjet.com/v3/REST/contact")
        suffix = url[base_len:]

        assert "../" not in suffix
        assert "..\\" not in suffix
        assert "\x00" not in suffix
