"""Regression tests for previously discovered security vulnerabilities and fuzzer artifacts."""

from __future__ import annotations

import base64
from contextlib import suppress
import tracemalloc
from typing import TYPE_CHECKING, Any
from unittest.mock import MagicMock, patch

import pytest
from requests.exceptions import RequestException

from mailjet_rest.client import AsyncClient, Client
from mailjet_rest.config import Config
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
from mailjet_rest.errors import ApiError, MailjetApiError, ValidationError
from mailjet_rest.utils.guardrails import SecretAuth, SecurityGuard


if TYPE_CHECKING:
    from collections.abc import Generator


@pytest.fixture
def client_v3() -> Generator[Client, None, None]:
    """Provide an offline-ready v3 Mailjet Client instance for regression tests."""
    with Client(auth=("test_pub", "test_priv"), version="v3") as client:
        yield client


class _StubErrorResponse:
    """Lightweight response stub for testing _handle_api_error without MagicMock leaks."""

    __slots__ = ("_json_payload", "_raise_val_err", "status_code", "text")

    def __init__(
        self,
        status_code: int,
        text: str,
        json_payload: Any = None,
        *,
        raise_val_err: bool = False,
    ) -> None:
        self.status_code = status_code
        self.text = text
        self._json_payload = json_payload
        self._raise_val_err = raise_val_err

    def json(self) -> Any:
        if self._raise_val_err:
            raise ValueError("Invalid JSON")
        return self._json_payload


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


# ==========================================
# 4. Fuzzer OOM Artifacts & Memory Stability
# ==========================================


class TestFuzzerOOMAndMemoryStability:
    """Regression tests for libFuzzer OOM artifacts and bounded heap growth across iterations."""

    def test_oom_artifact_577b9c1d_and_endpoint_memory_stability(self) -> None:
        """Regression test for oom-577b9c1da41cdd58a77a7b4f481a6a0022192e4d."""
        oom_bytes = base64.b64decode("Z2clYeE0IT5fX18lRkRERGwBAAAAAGdnZ20AAAAAAGcnZ6j3f1NkZgAAAHE=")

        class _StubPageConfig:
            __slots__ = ("api_url", "version")

            def __init__(self) -> None:
                self.version = "v3"
                self.api_url = "https://api.mailjet.com/"

        class _StubPageResponse:
            __slots__ = ("status_code", "text")

            def __init__(self) -> None:
                self.status_code = 200
                self.text = '{"Data": [{"ID": 1}]}'

            @staticmethod
            def json() -> dict[str, Any]:
                return {"Data": [{"ID": 1}]}

        class _StubPageClient:
            __slots__ = ("_resp", "config")

            def __init__(self) -> None:
                self.config = _StubPageConfig()
                self._resp = _StubPageResponse()

            def api_call(self, *_args: Any, **_kwargs: Any) -> _StubPageResponse:
                return self._resp

        stub_client: Any = _StubPageClient()

        raw_segment = oom_bytes.decode("utf-8", errors="replace")
        endpoint = Endpoint(name="contact", client=stub_client)
        with suppress(ValueError, TypeError, ValidationError, ApiError):
            endpoint.get(
                id=raw_segment[:15],
                action_id=raw_segment[15:25],
                filters={"sort": raw_segment[25:40]},
            )

        # Warm up one iteration outside tracemalloc to isolate steady-state allocation
        warm_ep = Endpoint(name="contactslist_csvdata", client=stub_client)
        warm_ep.get(id=0, filters={"limit": 10, "offset": "0"})
        for idx, _ in enumerate(warm_ep.stream(id=0, chunk_size=1)):
            if idx > 1:
                break

        tracemalloc.start()
        try:
            snapshot_before = tracemalloc.take_snapshot()

            for i in range(1000):
                ep = Endpoint(name="contactslist_csvdata", client=stub_client)
                with suppress(ValueError, TypeError, ValidationError, ApiError):
                    ep.get(id=i, filters={"limit": 10, "offset": "0"})
                    for idx, _ in enumerate(ep.stream(id=i, chunk_size=1)):
                        if idx > 1:
                            break

            snapshot_after = tracemalloc.take_snapshot()
            stats = snapshot_after.compare_to(snapshot_before, "lineno")
            total_growth_kb = sum(stat.size_diff for stat in stats) / 1024

            assert total_growth_kb < 512, f"Unexpected memory growth in Endpoint: {total_growth_kb:.2f} KB"
        finally:
            tracemalloc.stop()

    def test_oom_artifact_608a20a9_and_error_parser_memory_stability(self) -> None:
        """Regression test for oom-608a20a91c4c9530d41fce6fec617dedbca01939."""
        oom_bytes = base64.b64decode(
            "QT8FRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF"
            "RUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVFRUVF"
            "9Sdd"
        )
        raw_text = oom_bytes.decode("utf-8", errors="replace")

        edge_json_payloads: list[Any] = [
            {"ErrorMessage": raw_text},
            {"Messages": [{"Errors": [{"ErrorMessage": raw_text}]}]},
            "ErrorMessage",
            ["ErrorMessage"],
            {"Messages": [None]},
            {"Messages": [{"Errors": [None]}]},
            None,
            12345,
        ]

        for status in (400, 401, 403, 404, 429, 500, 503):
            for payload in edge_json_payloads:
                resp = _StubErrorResponse(status_code=status, text=raw_text, json_payload=payload)
                exc = RequestException("Simulated Fuzzed Exception", response=resp)  # type: ignore[arg-type]

                with pytest.raises(MailjetApiError) as exc_info:
                    Client._handle_api_error(exc)
                assert str(exc_info.value)

                with pytest.raises(MailjetApiError) as async_exc_info:
                    AsyncClient._handle_api_error(exc)
                assert str(async_exc_info.value)

        tracemalloc.start()
        try:
            snapshot_before = tracemalloc.take_snapshot()

            for i in range(1000):
                resp = _StubErrorResponse(
                    status_code=400 + (i % 5),
                    text=raw_text,
                    json_payload={"ErrorMessage": raw_text},
                )
                exc = RequestException("Simulated Fuzzed Exception", response=resp)  # type: ignore[arg-type]
                try:
                    Client._handle_api_error(exc)
                except ApiError as err:
                    _ = str(err)

            snapshot_after = tracemalloc.take_snapshot()
            stats = snapshot_after.compare_to(snapshot_before, "lineno")
            total_growth_kb = sum(stat.size_diff for stat in stats) / 1024

            assert total_growth_kb < 256, f"Unexpected memory growth in _handle_api_error: {total_growth_kb:.2f} KB"
        finally:
            tracemalloc.stop()

    def test_oom_artifact_86591c64_and_state_sequence_memory_stability(self) -> None:
        """Regression test for oom-86591c64eaf59cb124e1c25d91d34e3edb10e4ed."""
        oom_bytes = base64.b64decode("AQAAuAAAAAAJPqgAuAAAAAAJPg==")
        assert len(oom_bytes) > 0

        class _ZeroRetentionResponse:
            status_code = 200
            text = "{}"

            @staticmethod
            def raise_for_status() -> None:
                pass

            @staticmethod
            def json() -> dict[str, Any]:
                return {}

        with Client(auth=("test_pub", "test_priv"), version="v3") as client:
            initial_timeout = client.config.timeout
            stub_resp = _ZeroRetentionResponse()
            sess: Any = client.session
            sess.request = lambda *_args, **_kwargs: stub_resp

            for invalid_timeout in (-1.0, 0.0, float("nan"), float("inf"), 1e100, "invalid"):
                client.config.timeout = invalid_timeout  # type: ignore[assignment]
                with pytest.raises((ValueError, TypeError)):
                    client.contact.get()
                assert client.config.timeout == initial_timeout

            # Warm up endpoint cache before measuring steady-state heap growth
            client.contact.create(data={"Email": "warmup@example.com"})
            client.contact.get(id=0)
            client.send.create(data={"Messages": []})
            client.template.update(id=1, data={"Name": "tpl"})
            client.contact.delete(id=1)

            tracemalloc.start()
            try:
                snapshot_before = tracemalloc.take_snapshot()

                for i in range(1000):
                    client.contact.create(data={"Email": f"user{i}@example.com"})
                    client.contact.get(id=i)
                    client.send.create(data={"Messages": []})
                    client.template.update(id=1, data={"Name": "tpl"})
                    client.contact.delete(id=1)

                snapshot_after = tracemalloc.take_snapshot()
                stats = snapshot_after.compare_to(snapshot_before, "lineno")
                total_growth_kb = sum(stat.size_diff for stat in stats) / 1024

                assert total_growth_kb < 256, f"Unexpected memory growth in state sequence: {total_growth_kb:.2f} KB"
            finally:
                tracemalloc.stop()
