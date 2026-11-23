"""Regression tests for libFuzzer OOM artifacts, bounded memory stability, and Atheris fuzz targets."""

from __future__ import annotations

import ast
import base64
from contextlib import nullcontext, suppress
import importlib.util
import io
import json
import logging
from pathlib import Path
import sys
import tokenize
import tracemalloc
import types
from typing import Any
from unittest.mock import patch

import pytest
from requests.exceptions import RequestException

from mailjet_rest.client import AsyncClient, Client
from mailjet_rest.endpoint import Endpoint
from mailjet_rest.errors import ApiError, MailjetApiError, ValidationError
from tests.regression.conftest import REPO_ROOT


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
# Fuzzer OOM Artifacts & Memory Stability
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


# ==========================================
# Atheris Fuzz Target Helpers & Tests
# ==========================================


def _ensure_atheris_stub() -> tuple[Any, bool]:
    """Install a deterministic FuzzedDataProvider stub if atheris is unavailable."""
    if "atheris" in sys.modules:
        return sys.modules["atheris"], False

    stub = types.ModuleType("atheris")

    class _StubFDP:
        def __init__(self, data: bytes) -> None:
            self._data = data
            self._offset = 0

        def _next_byte(self) -> int:
            if not self._data:
                return 0
            val = self._data[self._offset % len(self._data)]
            self._offset += 1
            return val

        def ConsumeIntInRange(self, low: int, high: int) -> int:
            span = max(1, high - low + 1)
            return low + (self._next_byte() % span)

        def ConsumeInt(self, n: int) -> int:
            return self._next_byte() % max(1, n)

        def ConsumeBool(self) -> bool:
            return (self._next_byte() & 1) == 1

        def ConsumeBytes(self, count: int) -> bytes:
            return self._data[:count]

        def ConsumeUnicodeNoSurrogates(self, count: int) -> str:
            return self._data.decode("utf-8", errors="ignore")[:count]

        def ConsumeFloat(self) -> float:
            return float(self._next_byte()) / 10.0

        def ConsumeFloatInRange(self, low: float, high: float) -> float:
            span = max(0.0, high - low)
            return low + (self._next_byte() / 255.0) * span

        def PickValueInList(self, items: Any) -> Any:
            seq = list(items)
            return seq[self._next_byte() % len(seq)]

    stub.FuzzedDataProvider = _StubFDP  # type: ignore[attr-defined]
    stub.instrument_imports = lambda **_kwargs: nullcontext()  # type: ignore[attr-defined]
    stub.instrument_all = lambda: None  # type: ignore[attr-defined]
    stub.Setup = lambda *_args, **_kwargs: None  # type: ignore[attr-defined]
    stub.Fuzz = lambda: None  # type: ignore[attr-defined]
    sys.modules["atheris"] = stub
    return stub, True


def _resolve_fuzz_path(filename: str) -> Path:
    """Locate a unique fuzzer file anywhere under scope-organized tests/fuzz subdirectories."""
    matches = sorted((REPO_ROOT / "tests" / "fuzz").rglob(filename))
    assert len(matches) == 1, f"Expected unique match for {filename!r} under tests/fuzz, got {matches}"
    return matches[0]


def _load_fuzz_module(filename: str, alias: str) -> Any:
    fuzz_path = _resolve_fuzz_path(filename)
    spec = importlib.util.spec_from_file_location(alias, fuzz_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[alias] = module
    spec.loader.exec_module(module)
    return module


def _cleanup_async_fuzz_module(mod: Any, alias: str) -> None:
    loop = getattr(mod, "_loop", None)
    for attr in ("_base_async_client", "_aclient"):
        client_obj = getattr(mod, attr, None)
        if client_obj is not None and loop is not None and not loop.is_closed():
            loop.run_until_complete(client_obj.aclose())
    if loop is not None and not loop.is_closed():
        loop.close()
    sys.modules.pop(alias, None)


def test_fuzz_client_uses_real_attach_methods_gates_5mb_and_reuses_client() -> None:
    """PR #179 #14f: fuzz_client calls attach_file/attach_inline, gates >5MB branch to ~1%, and reuses Client."""
    src = _resolve_fuzz_path("fuzz_client.py").read_text(encoding="utf-8")
    assert "add_attachment" not in src
    assert "attach_file" in src
    assert "attach_inline" in src
    assert "ConsumeIntInRange(0, 99) == 0" in src

    tree = ast.parse(src)
    test_one_input = next(
        node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "TestOneInput"
    )
    has_module_level_client = any(
        isinstance(node, (ast.Assign, ast.AnnAssign))
        and any(
            isinstance(call, ast.Call) and isinstance(call.func, ast.Name) and call.func.id == "Client"
            for call in ast.walk(node)
        )
        for node in tree.body
    )
    assert has_module_level_client, "fuzz_client must reuse a module-level Client"

    client_with_blocks = [
        node
        for node in ast.walk(test_one_input)
        if isinstance(node, ast.With)
        and any(
            isinstance(item.context_expr, ast.Call)
            and isinstance(item.context_expr.func, ast.Name)
            and item.context_expr.func.id == "Client"
            for item in node.items
        )
    ]
    assert not client_with_blocks, (
        "TestOneInput must not rebuild Client TLS sessions inside a `with Client(...)` per iteration"
    )

    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_client_under_test"
    try:
        mod = _load_fuzz_module("fuzz_client.py", alias)
        for seed in (b"short", bytes([3]) + b"sender@example.com_fuzz_payload_padding_0123456789"):
            mod.TestOneInput(seed)
    finally:
        logging.disable(prev_disable)
        mod_obj = sys.modules.pop(alias, None)
        if mod_obj is not None and getattr(mod_obj, "_base_client", None) is not None:
            mod_obj._base_client.close()
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_builder_seeds_example_com_and_smoke() -> None:
    """PR #179 #14f: fuzz_builder seeds @example.com senders and runs clean smoke passes without AttributeError traps."""
    src = _resolve_fuzz_path("fuzz_builder.py").read_text(encoding="utf-8")
    assert "@example.com" in src

    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_builder_under_test"
    try:
        mod = _load_fuzz_module("fuzz_builder.py", alias)
        mod.TestOneInput(b"short")
        for b0 in range(10):
            mod.TestOneInput(bytes([b0]) + b"fuzz_builder_padding_0123456789abcdef")
    finally:
        logging.disable(prev_disable)
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_async_client_reraises_unexpected_gather_exceptions() -> None:
    """PR #179 #14f: fuzz_async_client must inspect gather results and re-raise unexpected exceptions."""
    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_async_client_under_test"
    mod: Any = None
    try:
        mod = _load_fuzz_module("fuzz_async_client.py", alias)
        base_client: Any = mod._base_async_client
        if base_client is None:
            pytest.skip("httpx2 not installed")
        assert base_client is not None

        async def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise KeyError("unexpected gather crash")

        # Mode 3 triggers asyncio.gather when ConsumeIntInRange(0, 3) == 3 (byte 0 % 4 == 3).
        with patch.object(type(base_client.contact), "get", side_effect=_boom):
            with pytest.raises(RuntimeError, match="UNHANDLED CRASH"):
                mod.TestOneInput(bytes([3]) + b"gather_mode_case")
    finally:
        logging.disable(prev_disable)
        if mod is not None:
            _cleanup_async_fuzz_module(mod, alias)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_async_evil_server_does_not_swallow_raw_httpx2_or_json_errors() -> None:
    """PR #179 #14f: fuzz_async_evil_server uses contextlib.aclosing and does not swallow raw httpx2/JSON errors."""
    src = _resolve_fuzz_path("fuzz_async_evil_server.py").read_text(encoding="utf-8")
    assert "aclosing" in src

    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_async_evil_server_under_test"
    mod: Any = None
    try:
        mod = _load_fuzz_module("fuzz_async_evil_server.py", alias)
        if mod._aclient is None or mod.httpx2 is None:
            pytest.skip("httpx2 not installed")

        async def _leak_httpx2(*_args: Any, **_kwargs: Any) -> Any:
            raise mod.httpx2.HTTPError("raw transport leaked")

        async def _leak_json(*_args: Any, **_kwargs: Any) -> Any:
            raise json.JSONDecodeError("raw json leaked", "{", 1)

        with patch.object(type(mod._aclient), "api_call", side_effect=_leak_httpx2):
            with pytest.raises(RuntimeError, match="CRITICAL"):
                mod.TestOneInput(b"\x01" * 24)

        with patch.object(type(mod._aclient), "api_call", side_effect=_leak_json):
            with pytest.raises(RuntimeError, match="CRITICAL"):
                mod.TestOneInput(b"\x01" * 24)

        # Normal evil responses must still be handled cleanly via ApiError/MailjetApiError.
        for b0 in (0, 1, 2):
            mod.TestOneInput(bytes([b0]) + b"evil_server_fuzz_padding_0123456789")
    finally:
        logging.disable(prev_disable)
        if mod is not None:
            _cleanup_async_fuzz_module(mod, alias)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_webhooks_checks_valid_hmac_roundtrip_and_empty_secret() -> None:
    """PR #179 #14f: fuzz_webhooks asserts valid HMAC-SHA256 returns True (false-rejection check) & handles empty secret."""
    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_webhooks_under_test"
    try:
        mod = _load_fuzz_module("fuzz_webhooks.py", alias)

        # Mode 0 with empty/whitespace secret must be handled cleanly via ValueError.
        mod.TestOneInput(bytes([0]) + b"   \x00\x00\x00\x00\x00")

        # Mode 1 must fail with AssertionError if verify_webhook_signature falsely rejects a valid digest.
        # Under _StubFDP, byte 0=1 selects mode=1 and trailing 0xff bytes yield delta=-245, max_age=255 (within window).
        valid_window_seed = bytes([1]) + b"\xff" * 31
        with patch.object(mod, "verify_webhook_signature", return_value=False):
            with pytest.raises(AssertionError):
                mod.TestOneInput(valid_window_seed)

        # Real verify_webhook_signature succeeds cleanly on mode 1.
        mod.TestOneInput(valid_window_seed)
    finally:
        logging.disable(prev_disable)
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_jitter_retry_asserts_math_isfinite() -> None:
    """PR #179 #14f: fuzz_jitter_retry rejects non-finite NaN/inf delays on compute_retry_delay & parse_retry_after_http_date."""
    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    alias = "fuzz_jitter_retry_under_test"
    try:
        mod = _load_fuzz_module("fuzz_jitter_retry.py", alias)

        # Byte 0=200 => total_retries=199, byte 2=0 => num_errors=0 so Retry-After paths always execute.
        jitter_seed = bytes([200, 1, 0, 0, 0, 0, 0, 0])
        with patch.object(mod, "compute_retry_delay", return_value=float("nan")):
            with pytest.raises(RuntimeError, match="non-finite|finite|NaN|CRASH"):
                mod.TestOneInput(jitter_seed)

        with patch.object(mod, "parse_retry_after_http_date", return_value=float("nan")):
            with pytest.raises(RuntimeError, match="non-finite|finite|NaN|CRASH"):
                mod.TestOneInput(jitter_seed)
    finally:
        logging.disable(prev_disable)
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)


def test_all_fuzz_targets_document_empty_except_pass_handlers() -> None:
    """CodeQL #85/#86 (py/empty-except): every except ...: pass in tests/fuzz/**/fuzz_*.py must include a rationale comment."""
    fuzz_files = sorted((REPO_ROOT / "tests" / "fuzz").rglob("fuzz_*.py"))
    assert len(fuzz_files) == 36
    uncommented: list[str] = []
    for fuzz_file in fuzz_files:
        source = fuzz_file.read_text(encoding="utf-8")
        comment_lines = {
            tok.start[0]
            for tok in tokenize.generate_tokens(io.StringIO(source).readline)
            if tok.type == tokenize.COMMENT
        }
        tree = ast.parse(source, filename=str(fuzz_file))
        for node in ast.walk(tree):
            if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
                end_line = node.end_lineno or node.lineno
                has_comment = any(node.lineno <= ln <= end_line for ln in comment_lines)
                if not has_comment:
                    uncommented.append(f"{fuzz_file.name}:{node.lineno}")

    assert not uncommented, f"Empty except...pass handlers missing explanatory comments: {uncommented}"
