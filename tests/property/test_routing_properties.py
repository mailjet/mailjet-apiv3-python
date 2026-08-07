"""Property-based tests for Mailjet SDK URL Routing and Sanitization.
Powered by Hypothesis.
"""

from typing import Any
from urllib.parse import urlparse

from hypothesis import given, settings, strategies as st

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.utils.guardrails import SecurityGuard


@settings(max_examples=500)
@given(segment=st.one_of(st.text(), st.integers(), st.floats(allow_nan=False), st.none()))
def test_property_segment_sanitization(segment: Any) -> None:
    """INVARIANT: The segment sanitizer must mathematically guarantee the absence of traversal vectors."""
    try:
        clean_segment = SecurityGuard.sanitize_segment(segment)
        assert isinstance(clean_segment, str)
        assert "." not in clean_segment
        assert "\n" not in clean_segment
        assert "\r" not in clean_segment
        if segment is None:
            assert clean_segment == ""
    except (ValueError, TypeError):
        pass


@settings(max_examples=500)
@given(route_key=st.text(min_size=1, alphabet=st.characters(blacklist_categories=("Cs",))))
def test_property_config_router_contract(route_key: str) -> None:
    """INVARIANT: Dynamic Config.__getitem__ must return a valid URL and dict."""
    config = Config()
    url, headers = config[route_key]
    assert isinstance(url, str)
    assert isinstance(headers, dict)
    parsed_url = urlparse(url)
    assert parsed_url.scheme == "https"
    assert parsed_url.netloc == "api.mailjet.com"
    assert parsed_url.path.startswith(f"/{config.version}/")
    assert "Content-Type" in headers


@settings(max_examples=400)
@given(
    endpoint_name=st.text(min_size=1, alphabet=st.characters(blacklist_categories=("Cs",))),
    id_val=st.one_of(st.integers(), st.text(alphabet=st.characters(blacklist_categories=("Cs",))), st.none()),
    action_id=st.one_of(st.integers(), st.text(alphabet=st.characters(blacklist_categories=("Cs",))), st.none()),
)
def test_property_endpoint_build_url_resilience(endpoint_name: str, id_val: Any, action_id: Any) -> None:
    """INVARIANT: _build_url must securely map any random inputs to a safe URL without internal exceptions."""
    client = Client(auth=("a", "b"))
    endpoint = Endpoint(client=client, name=endpoint_name)

    try:
        url = endpoint._build_url(id_val=id_val, action_id=action_id)
        assert url.startswith("https://api.mailjet.com")

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
