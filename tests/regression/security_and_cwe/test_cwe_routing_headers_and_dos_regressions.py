"""CWE regression tests for URI routing, header injection, secrets, type confusion, and DoS limits."""

from __future__ import annotations

import base64
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

from mailjet_rest.client import Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
from mailjet_rest.errors import ValidationError
from mailjet_rest.utils.guardrails import SecretAuth, SecurityGuard


# ==========================================
# 1. Path Traversal & URI Routing (CWE-22)
# ==========================================


class TestPathTraversalAndRoutingSecurity:
    """CWE-22 regression tests for static registry and dynamic fallback URI construction."""

    def test_csv_routing_traversal_prevention(self, client_v3: Client) -> None:
        """Ensure path traversal payloads are blocked in CSV data URL construction."""
        endpoint = client_v3.contactslist_csvdata

        with pytest.raises(ValueError, match="Path traversal attempt"):
            endpoint._build_url(id_val="../secret")

    def test_cwe22_registry_uri_interpolation_traversal_prevention(self, client_v3: Client) -> None:
        """Ensure path traversal payloads in dynamic '{id}' segments are strictly rejected."""
        endpoint = client_v3.templates_contents

        with (
            pytest.warns(DeprecationWarning, match="templates_contents"),
            pytest.raises(ValueError, match="Path traversal attempt"),
        ):
            endpoint._build_url(id_val="..")

    @pytest.mark.parametrize(
        "malicious_name",
        [
            "../admin",
            "..\\admin",
            " safe/../evil_action",
            "res\x00name",
        ],
    )
    def test_cwe22_dynamic_endpoint_resource_traversal_prevention(
        self,
        client_v3: Client,
        malicious_name: str,
    ) -> None:
        """Ensure dynamic endpoint names cannot inject traversal or null bytes."""
        ep_sync = Endpoint(client=client_v3, name=malicious_name)
        ep_async = AsyncEndpoint(client=client_v3, name=malicious_name)

        with pytest.raises(ValueError):
            ep_sync._build_url()
        with pytest.raises(ValueError):
            ep_async._build_url()

    def test_cwe22_crash_artifact_7fdc6ff6_and_version_traversal_prevention(
        self,
        client_v3: Client,
    ) -> None:
        """Regression test for crash-7fdc6ff658d0f0f203c9dfd2fdc49309fdd8f88f."""
        crash_bytes = base64.b64decode("x/+o39/f39/fc2MvcHJpdmF0ZS9UbS4uL3RtcHJpcmlwdN/f399kaWM0dDov9P8Abko=")
        raw_str = crash_bytes.decode("utf-8", errors="replace")

        ep_crash = Endpoint(client=client_v3, name=raw_str)
        with pytest.raises(ValueError):
            ep_crash._build_url()

        client_v3.config.version = "../v1"
        ep_valid = Endpoint(client=client_v3, name="contact")
        with pytest.raises(ValueError, match="Path traversal attempt"):
            ep_valid._build_url()


# ==========================================
# 2. Header Injection, Client Exposure & Secrets (CWE-113, CWE-668, CWE-316)
# ==========================================


class TestHeaderAndClientBoundarySecurity:
    """CWE-113, CWE-668, and CWE-316 regression tests for headers, attributes, and SecretAuth."""

    def test_cwe113_header_injection_crlf_prevention(self, client_v3: Client) -> None:
        """Ensure CRLF characters in custom headers are blocked before the network layer (CWE-113)."""
        malicious_headers = {
            "X-Custom-Header": "innocent_value\r\nEvil-Spoofed-Header: admin_access",
            "Another": "normal\n",
        }

        with pytest.raises(ValueError, match="(?i)crlf injection detected"):
            client_v3.contact.get(headers=malicious_headers)

    def test_cwe668_client_private_attribute_exposure_prevention(self, client_v3: Client) -> None:
        """Ensure Client explicitly denies access to undefined or private internal methods (CWE-668)."""
        with pytest.raises(AttributeError, match="'Client' object has no attribute '_parse_response'"):
            _ = client_v3._parse_response

    def test_cwe316_secret_auth_repr_invariance_and_artifact_4179a28c(self) -> None:
        """Regression test for crash-4179a28cf76d0600a681701bf65598094f93aeac."""
        crash_bytes = base64.b64decode("5VJFREFDVEVE")
        decoded_str = crash_bytes.decode("latin1")

        for key_candidate in (decoded_str, "REDACTED", "SecretAuth", "super_secret_api_key_12345"):
            auth = SecretAuth((key_candidate, "valid_secret"))
            assert repr(auth) == "SecretAuth(***REDACTED***)"
            assert str(auth) == "SecretAuth(***REDACTED***)"

            with pytest.raises(TypeError, match="CWE-316"):
                _ = auth[0]
            with pytest.raises(TypeError, match="CWE-316"):
                _ = list(auth)

        with pytest.raises(ValueError, match="forbidden control characters"):
            SecretAuth(("key\r\nInjected: 1", "secret"))

        with pytest.raises(ValueError):
            SecretAuth((crash_bytes.decode("utf-8", errors="replace"), "valid_secret"))


# ==========================================
# 3. Config Type Confusion & DoS Limits (CWE-843, CWE-400)
# ==========================================


class TestConfigAndParserDoSProtection:
    """CWE-843 and CWE-400 regression tests for timeout bounds and HTML parser DoS protection."""

    def test_cwe843_config_timeout_type_confusion(self) -> None:
        """Ensure Config enforces runtime numeric type validation on timeouts (CWE-843)."""
        with pytest.raises(TypeError, match="(?i)numeric"):
            Config(api_url="https://api.mailjet.com/", timeout="malicious_string")  # type: ignore[arg-type]

    @pytest.mark.parametrize(
        "excessive_timeout",
        [
            1e300,
            (1e300, 10.0),
            10**5000,
        ],
        ids=["float_1e300", "tuple_1e300", "int_10_pow_5000"],
    )
    def test_cwe400_excessive_and_astronomical_timeout_rejection(self, excessive_timeout: Any) -> None:
        """Ensure extreme floats/integers causing C-level or float overflow are rejected (CWE-400)."""
        with pytest.raises(ValueError, match="Timeout value is out of range or invalid|exceeds maximum allowed limit"):
            Config(timeout=excessive_timeout)

    @patch("mailjet_rest.utils.guardrails.SecurityGuard._SpamGuardParser.feed")
    def test_html_safety_dos_protection_rejects_malformed_tags(self, mock_feed: MagicMock) -> None:
        """Regression test for fuzzing crash-84534e0c7ecc6f0674e9283079563e63300cd0b3."""
        mock_feed.side_effect = RecursionError("Simulated memory exhaustion")
        malicious_payload = "<![<!doctypee\x00969866"

        with pytest.raises(ValidationError) as exc_info:
            SecurityGuard.analyze_html_safety(malicious_payload)

        assert "Fatal HTML parsing error" in str(exc_info.value)
        assert "DoS protection triggered" in str(exc_info.value)
