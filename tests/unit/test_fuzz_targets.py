"""Unit tests verifying fuzz harness target registration and dispatch."""

from __future__ import annotations

import contextlib
import importlib
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
