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
    assert len(fuzz_files) == 30

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


def _import_async_fuzz_target(mod_name: str) -> Any:
    """Import an allowlisted async fuzz target using literal module strings."""
    if mod_name == "tests.fuzz.fuzz_async_client":
        return importlib.import_module("tests.fuzz.fuzz_async_client")
    if mod_name == "tests.fuzz.fuzz_async_endpoint":
        return importlib.import_module("tests.fuzz.fuzz_async_endpoint")
    if mod_name == "tests.fuzz.fuzz_async_evil_server":
        return importlib.import_module("tests.fuzz.fuzz_async_evil_server")
    msg = f"Unexpected async fuzz module: {mod_name!r}"
    raise ImportError(msg)


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
            fuzz_mod = _import_async_fuzz_target(mod_name)
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


def test_fuzzer_dict_format_and_build_sh_wiring() -> None:
    """Every entry in tests/fuzz/fuzzer.dict is sorted, pure-ASCII, valid 1..128 bytes, and wired into build.sh."""
    import scripts.harvest_fuzzer_dict as harvester  # ruff: ignore[import-outside-top-level]

    dict_path = Path("tests/fuzz/fuzzer.dict")
    lines = dict_path.read_text(encoding="utf-8").splitlines()
    assert lines == sorted(lines), "tests/fuzz/fuzzer.dict must remain lexicographically sorted"
    assert len(lines) == len(set(lines)), "tests/fuzz/fuzzer.dict must not contain duplicate lines"

    for idx, line in enumerate(lines, start=1):
        assert line.isascii(), f"Line {idx} contains non-ASCII characters: {line!r}"
        decoded = harvester.parse_dict_line(line)
        assert decoded is not None, f"Line {idx} is not a valid quoted dict entry: {line!r}"
        assert 1 <= len(decoded) <= 128, f"Line {idx} exceeds 1..128 byte bound: len={len(decoded)}"

    build_sh = Path(".clusterfuzzlite/build.sh").read_text(encoding="utf-8")
    assert "tests/fuzz/fuzzer.dict" in build_sh
    assert "${OUT}/${fuzzer_basename}.dict" in build_sh


def test_harvest_fuzzer_dict_octal_to_hex_and_non_destructive_merge(tmp_path: Path) -> None:
    """Harvester decodes libFuzzer octal escapes, respects max length, shields secrets, and preserves existing entries."""
    from collections import Counter  # ruff: ignore[import-outside-top-level]

    import scripts.harvest_fuzzer_dict as harvester  # ruff: ignore[import-outside-top-level]

    sample_log = "\n".join(
        [
            "2026-11-17T11:00:12.5918422Z ###### Recommended dictionary. ######",
            '2026-11-17T11:00:12.5918636Z "__parameters__" # Uses: 1276',
            '2026-11-17T11:00:12.5918841Z "\\011\\000\\000\\000\\000\\000\\000\\000" # Uses: 1064',
            '2026-11-17T11:00:12.5919061Z "\\377\\377\\377\\377\\377\\377\\377\\374" # Uses: 933',
            '2026-11-17T11:00:12.5919245Z "https://u:p@api.mailjet.com/v3" # Uses: 50',
            f'2026-11-17T11:00:12.5919400Z "{"A" * 130}" # Uses: 10',
            "2026-11-17T11:00:12.5919895Z ###### End of recommended dictionary. ######",
        ]
    )
    extracted = harvester.extract_recommended_from_text(sample_log)
    assert extracted[b"__parameters__"] == 1276
    assert extracted[b"\x09\x00\x00\x00\x00\x00\x00\x00"] == 1064
    assert extracted[b"\xff\xff\xff\xff\xff\xff\xff\xfc"] == 933
    assert b"A" * 130 not in extracted

    temp_dict = tmp_path / "fuzzer.dict"
    temp_dict.write_text('"existing"\n', encoding="utf-8")
    _, added, merged = harvester.merge_dictionary(temp_dict, Counter(extracted), write=True)
    assert added == 4
    assert '"existing"' in merged
    assert '"__parameters__"' in merged
    assert '"\\x09\\x00\\x00\\x00\\x00\\x00\\x00\\x00"' in merged
    assert '"\\xff\\xff\\xff\\xff\\xff\\xff\\xff\\xfc"' in merged
    assert any(line.startswith('"\\x68\\x74\\x74\\x70\\x73\\x3a') for line in merged)
    assert harvester.main(["--dict-path", str(temp_dict), "--sync-routes", "--dry-run"]) == 0


def test_harvest_fuzzer_dict_github_https_get_security() -> None:
    """Harvester validates GitHub/Blob URLs and strips Authorization before Azure redirect."""
    from unittest.mock import patch  # ruff: ignore[import-outside-top-level]

    import pytest  # ruff: ignore[import-outside-top-level]
    import requests  # ruff: ignore[import-outside-top-level]

    import scripts.harvest_fuzzer_dict as harvester  # ruff: ignore[import-outside-top-level]

    scheme_user = "https://user"
    bad_urls = [
        "http://api.github.com/repos/mailjet/mailjet-apiv3-python",
        "https://evil.example.com/logs.zip",
        "https://.blob.core.windows.net/logs.zip",
        f"{scheme_user}:placeholder@api.github.com/repos/mailjet/mailjet-apiv3-python",
        "https://api.github.com:8443/repos/mailjet/mailjet-apiv3-python",
    ]
    for bad in bad_urls:
        with pytest.raises(ValueError, match="Disallowed GitHub log URL"):
            harvester._build_validated_github_url(bad)

    calls: list[dict[str, Any]] = []

    class _FakeResp:
        def __init__(self, status_code: int, content: bytes, headers: dict[str, str]) -> None:
            self.status_code = status_code
            self.content = content
            self.headers = headers

    def _fake_get(url: str, *, headers: dict[str, str], timeout: float, verify: bool, allow_redirects: bool) -> Any:
        calls.append(
            {
                "url": url,
                "headers": dict(headers),
                "timeout": timeout,
                "verify": verify,
                "allow_redirects": allow_redirects,
            }
        )
        if len(calls) == 1:
            return _FakeResp(
                302,
                b"",
                {"Location": "https://pipelines.blob.core.windows.net/logs/1.txt?sig=abc"},
            )
        return _FakeResp(200, b"ok-log-bytes", {"Content-Type": "text/plain"})

    with patch.object(requests, "get", side_effect=_fake_get):
        status, body, _ = harvester._github_https_get(
            "https://api.github.com/repos/mailjet/mailjet-apiv3-python/actions/jobs/1/logs",
            "tok_test",
        )

    assert status == 200
    assert body == b"ok-log-bytes"
    assert len(calls) == 2
    assert calls[0]["headers"]["Authorization"] == "Bearer tok_test"
    assert "Authorization" not in calls[1]["headers"]
    assert all(c["timeout"] == 30.0 and c["verify"] is True and c["allow_redirects"] is False for c in calls)

    with pytest.raises(ValueError, match="Invalid repository slug"):
        harvester.collect_from_github("not a slug", [], 30, [], [])

    with pytest.raises(ValueError, match="Invalid workflow filename"):
        harvester.collect_from_github("mailjet/mailjet-apiv3-python", ["../bad.yml"], 30, [], [])


def test_harvest_fuzzer_dict_skips_processed_ci_runs_and_jobs(tmp_path: Path) -> None:
    """Harvester only fetches GitHub logs for run_ids and job_ids not yet in state."""
    from unittest.mock import patch  # ruff: ignore[import-outside-top-level]

    import scripts.harvest_fuzzer_dict as harvester  # ruff: ignore[import-outside-top-level]

    state_path = tmp_path / ".harvest_state.json"
    harvester.save_harvest_state(state_path, {101}, {201})
    loaded_runs, loaded_jobs = harvester.load_harvest_state(state_path)
    assert loaded_runs == {101}
    assert loaded_jobs == {201}

    fetched_urls: list[str] = []

    def _fake_https_get(url: str, _token: str | None) -> tuple[int, bytes, dict[str, str]]:
        fetched_urls.append(url)
        if url.endswith("/jobs/202/logs"):
            log = (
                "###### Recommended dictionary. ######\n"
                '"fresh_ci_token" # Uses: 5\n'
                "###### End of recommended dictionary. ######\n"
            )
            return 200, log.encode("utf-8"), {}
        return 404, b"", {}

    with patch.object(harvester, "_github_https_get", side_effect=_fake_https_get):
        counts = harvester.collect_from_github(
            "mailjet/mailjet-apiv3-python",
            [],
            30,
            [201, 202],
            [101, 102],
            processed_run_ids=loaded_runs,
            processed_job_ids=loaded_jobs,
        )

    assert all("/runs/101/" not in u and "/jobs/201/" not in u for u in fetched_urls)
    assert any("/runs/102/logs" in u for u in fetched_urls)
    assert any("/jobs/202/logs" in u for u in fetched_urls)
    assert counts[b"fresh_ci_token"] == 5
    assert 202 in loaded_jobs


def test_fuzz_webhooks_target_smoke() -> None:
    """Verify fuzz_webhooks target imports cleanly and handles mode 0, 1, 2 inputs."""
    _, injected = _ensure_atheris_stub()
    try:
        sys.modules.pop("tests.fuzz.fuzz_webhooks", None)
        fuzz_mod = importlib.import_module("tests.fuzz.fuzz_webhooks")
        fuzz_mod.TestOneInput(b"short")
        for mode_byte in (0, 1, 2):
            fuzz_mod.TestOneInput(bytes([mode_byte]) + b"webhook_payload_fuzz_seed_bytes_12345678")
    finally:
        sys.modules.pop("tests.fuzz.fuzz_webhooks", None)
        if injected:
            sys.modules.pop("atheris", None)
