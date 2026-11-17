"""Unit tests verifying fuzz harness target registration and dispatch."""

from __future__ import annotations

import ast
import contextlib
import importlib
from pathlib import Path
import sys
import types
import warnings
from typing import Any


def _ensure_atheris_stub() -> tuple[Any, bool]:
    """Return loaded atheris or install a minimal test stub in sys.modules."""
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
            text = self._data.decode("utf-8", errors="ignore")
            return text[:count]

        def ConsumeFloat(self) -> float:
            return float(self._next_byte()) / 10.0

        def ConsumeFloatInRange(self, low: float, high: float) -> float:
            span = max(0.0, high - low)
            return low + (self._next_byte() / 255.0) * span

        def PickValueInList(self, items: Any) -> Any:
            seq = list(items)
            return seq[self._next_byte() % len(seq)]

    stub.FuzzedDataProvider = _StubFDP  # type: ignore[attr-defined]
    stub.instrument_imports = lambda **_kwargs: contextlib.nullcontext()  # type: ignore[attr-defined]
    stub.instrument_all = lambda: None  # type: ignore[attr-defined]
    stub.Setup = lambda *_args, **_kwargs: None  # type: ignore[attr-defined]
    stub.Fuzz = lambda: None  # type: ignore[attr-defined]
    sys.modules["atheris"] = stub
    return stub, True


def test_fuzz_guardrails_dispatches_all_eight_targets() -> None:
    """CRIT-05: Ensure all 8 fuzz targets (indices 0..7) are registered and runnable."""
    _, injected = _ensure_atheris_stub()
    try:
        sys.modules.pop("tests.fuzz.fuzz_guardrails", None)
        fuzz_mod = importlib.import_module("tests.fuzz.fuzz_guardrails")

        assert len(fuzz_mod._TARGETS) == 8

        # Short input must return cleanly without crashing.
        fuzz_mod.TestOneInput(b"abc")

        # Exercise every target index 0..7 explicitly.
        sample_bodies = (
            b"safe_file.txt",
            b"X-Header: value\r\n",
            b"trace\nid\r",
            b"http://proxy.example.com:8080",
            b"hello\x00world",
            b"bearer_token_sample_12345",
            b"<p>hello</p><script/>",
            b"verify",
        )
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            for idx, body in enumerate(sample_bodies):
                fuzz_mod.TestOneInput(bytes([idx]) + body + b"_pad_bytes")
    finally:
        sys.modules.pop("tests.fuzz.fuzz_guardrails", None)
        if injected:
            sys.modules.pop("atheris", None)


def _is_atheris_call(node: ast.AST, attr: str) -> bool:
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "atheris"
        and node.func.attr == attr
    )


def _is_scoped_instrument_with(node: ast.stmt) -> bool:
    if not isinstance(node, ast.With):
        return False
    for item in node.items:
        call = item.context_expr
        if not _is_atheris_call(call, "instrument_imports"):
            continue
        assert isinstance(call, ast.Call)
        for kw in call.keywords:
            if (
                kw.arg == "include"
                and isinstance(kw.value, ast.List)
                and any(isinstance(elt, ast.Constant) and elt.value == "mailjet_rest" for elt in kw.value.elts)
            ):
                return True
    return False


def _imports_mailjet_rest(node: ast.AST) -> bool:
    if isinstance(node, ast.Import):
        return any(alias.name == "mailjet_rest" or alias.name.startswith("mailjet_rest.") for alias in node.names)
    if isinstance(node, ast.ImportFrom):
        return node.module is not None and (node.module == "mailjet_rest" or node.module.startswith("mailjet_rest."))
    return False


def test_all_fuzz_targets_scope_instrumentation_to_mailjet_rest() -> None:
    """Ensure every Atheris target scopes import instrumentation to mailjet_rest and avoids instrument_all()."""
    fuzz_files = sorted(Path("tests/fuzz").glob("fuzz_*.py"))
    assert len(fuzz_files) == 29

    for fuzz_file in fuzz_files:
        tree = ast.parse(fuzz_file.read_text(encoding="utf-8"), filename=str(fuzz_file))

        instrument_all_calls = [node for node in ast.walk(tree) if _is_atheris_call(node, "instrument_all")]
        assert not instrument_all_calls, f"{fuzz_file} must not call atheris.instrument_all()"

        for node in ast.walk(tree):
            if _is_atheris_call(node, "instrument_imports"):
                assert isinstance(node, ast.Call)
                bad_override = any(
                    kw.arg == "enable_loader_override"
                    and isinstance(kw.value, ast.Constant)
                    and kw.value.value is False
                    for kw in node.keywords
                )
                assert not bad_override, (
                    f"{fuzz_file} must not pass enable_loader_override=False to instrument_imports()"
                )

        scoped_with_blocks = [stmt for stmt in tree.body if _is_scoped_instrument_with(stmt)]
        assert scoped_with_blocks, (
            f"{fuzz_file} must import mailjet_rest inside atheris.instrument_imports(include=['mailjet_rest'])"
        )

        for stmt in tree.body:
            if _is_scoped_instrument_with(stmt):
                continue
            unscoped = [sub for sub in ast.walk(stmt) if _imports_mailjet_rest(sub)]
            assert not unscoped, f"{fuzz_file} imports mailjet_rest outside scoped instrument_imports block"


def test_async_fuzz_targets_smoke() -> None:
    """Verify the three async Atheris fuzz targets import and process sample inputs cleanly."""
    _, injected = _ensure_atheris_stub()
    async_modules = (
        "tests.fuzz.fuzz_async_client",
        "tests.fuzz.fuzz_async_endpoint",
        "tests.fuzz.fuzz_async_evil_server",
    )
    loaded_mods: list[Any] = []
    try:
        for mod_name in async_modules:
            sys.modules.pop(mod_name, None)
            fuzz_mod = importlib.import_module(mod_name)
            loaded_mods.append(fuzz_mod)

            fuzz_mod.TestOneInput(b"short")
            for mode_byte in (0, 1, 2):
                fuzz_mod.TestOneInput(bytes([mode_byte]) + b"fuzz_payload_padding_0123456789")
    finally:
        for fuzz_mod in loaded_mods:
            loop = getattr(fuzz_mod, "_loop", None)
            for client_attr in ("_base_async_client", "_aclient"):
                client_obj = getattr(fuzz_mod, client_attr, None)
                if client_obj is not None and loop is not None and not loop.is_closed():
                    loop.run_until_complete(client_obj.aclose())
            if loop is not None and not loop.is_closed():
                loop.close()
        for mod_name in async_modules:
            sys.modules.pop(mod_name, None)
        if injected:
            sys.modules.pop("atheris", None)
