"""Regression tests for previously discovered security vulnerabilities."""

import pytest
from mailjet_rest.client import Client
from mailjet_rest.config import Config


def test_csv_routing_traversal_prevention() -> None:
    """Ensure path traversal payloads are handled/blocked in URL construction."""
    client = Client(auth=("test_pub", "test_priv"), version="v3")

    # Instantiate the endpoint natively via the client
    endpoint = client.contactslist_csvdata

    # SecurityGuard.sanitize_segment strictly blocks path traversal characters
    with pytest.raises(ValueError, match="Path traversal attempt"):
        endpoint._build_url(id_val="../secret")


def test_cwe113_header_injection_crlf_prevention() -> None:
    """Ensure CRLF characters in custom headers are blocked (CWE-113)."""
    client = Client(auth=("test_pub", "test_priv"), version="v3")

    # Attacker attempts to inject a new HTTP header via newline injection
    malicious_headers = {
        "X-Custom-Header": "innocent_value\r\nEvil-Spoofed-Header: admin_access",
        "Another": "normal\n"
    }

    # The SecurityGuard must aggressively reject this before the network layer.
    # We call the endpoint directly to ensure the payload traverses the SDK's standard header compiler.
    with pytest.raises(ValueError, match="(?i)crlf injection detected"):
        client.contact.get(headers=malicious_headers)


def test_cwe22_registry_uri_interpolation_traversal_prevention() -> None:
    """Ensure path traversal payloads in dynamic '{id}' segments are strictly rejected."""
    client = Client(auth=("test_pub", "test_priv"), version="v3")

    # Inject path traversal payload into a middle-interpolated route
    # Route template: "REST/templates/{id}/contents"
    malicious_id = ".."
    endpoint = client.templates_contents

    # The output URL generation must completely neutralize and block the traversal
    with pytest.raises(ValueError, match="Path traversal attempt"):
        endpoint._build_url(id_val=malicious_id)


def test_cwe843_config_timeout_type_confusion() -> None:
    """Ensure the Config class enforces runtime type coercion instead of static casting."""
    with pytest.raises(TypeError, match="(?i)numeric"):
        Config(api_url="https://api.mailjet.com/", timeout="malicious_string")  # type: ignore[arg-type]


def test_cwe668_client_private_attribute_exposure_prevention() -> None:
    """Ensure the Client explicitly denies access to undefined or private internal methods (CWE-668).

    Regression test derived from a fuzzing crash where Atheris attempted
    to dynamically access a non-existent `_parse_response` method.
    """
    client = Client(auth=("test_pub", "test_priv"), version="v3")

    # Attempting to access an undefined private method must be intercepted by __getattr__
    # and strictly rejected.
    with pytest.raises(AttributeError, match="'Client' object has no attribute '_parse_response'"):
        _ = client._parse_response
