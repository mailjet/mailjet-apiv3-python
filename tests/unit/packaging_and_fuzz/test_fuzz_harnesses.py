"""Unit tests verifying fuzz harness target registration and dispatch."""

from __future__ import annotations

import ast
import contextlib
import importlib
import logging
import sys
import types
import warnings
from pathlib import Path
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
    prev_disable = logging.root.manager.disable
    mod_name = "tests.fuzz.security_and_guardrails.fuzz_guardrails"
    try:
        sys.modules.pop(mod_name, None)
        fuzz_mod = importlib.import_module("tests.fuzz.security_and_guardrails.fuzz_guardrails")

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
        logging.disable(prev_disable)
        sys.modules.pop(mod_name, None)
        if injected:
            sys.modules.pop("atheris", None)
    assert logging.root.manager.disable == prev_disable


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


def test_fuzz_suite_scope_organization_and_unique_basenames_gate() -> None:
    """Enforce scope-driven tests/fuzz package layout, dict/corpus root placement, and unique fuzzer basenames."""
    fuzz_root = Path("tests/fuzz")
    assert (fuzz_root / "__init__.py").is_file()
    assert (fuzz_root / "fuzzer.dict").is_file()

    root_fuzzers = sorted(fuzz_root.glob("fuzz_*.py"))
    assert not root_fuzzers, f"Flat fuzz_*.py files must live in scope subdirectories, found: {root_fuzzers}"

    expected_scopes = {
        "clients",
        "endpoints_and_routing",
        "builders_and_payloads",
        "security_and_guardrails",
        "transport_and_chaos",
        "webhooks_and_telemetry",
    }
    actual_scopes = {
        entry.name for entry in fuzz_root.iterdir() if entry.is_dir() and entry.name not in {"corpus", "__pycache__"}
    }
    assert actual_scopes == expected_scopes

    all_fuzzers: list[Path] = []
    for scope in sorted(expected_scopes):
        scope_dir = fuzz_root / scope
        assert (scope_dir / "__init__.py").is_file(), f"Missing __init__.py in {scope_dir}"
        scope_fuzzers = sorted(scope_dir.glob("fuzz_*.py"))
        assert len(scope_fuzzers) >= 3, f"Expected >= 3 fuzzers in {scope_dir}, got {len(scope_fuzzers)}"
        all_fuzzers.extend(scope_fuzzers)

    assert len(all_fuzzers) == 36
    basenames = [p.name for p in all_fuzzers]
    assert len(basenames) == len(set(basenames)), f"Duplicate fuzzer basenames collide in build.sh/logs: {basenames}"


def test_all_fuzz_targets_scope_instrumentation_to_mailjet_rest() -> None:
    """Ensure every Atheris target scopes import instrumentation to mailjet_rest and avoids instrument_all()."""
    fuzz_files = sorted(Path("tests/fuzz").rglob("fuzz_*.py"))
    assert len(fuzz_files) == 36

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


def _import_fuzz_target(mod_name: str) -> Any:
    """Import an allowlisted Atheris fuzz target using literal module strings."""
    if mod_name == "tests.fuzz.clients.fuzz_async_client":
        return importlib.import_module("tests.fuzz.clients.fuzz_async_client")
    if mod_name == "tests.fuzz.endpoints_and_routing.fuzz_async_endpoint":
        return importlib.import_module("tests.fuzz.endpoints_and_routing.fuzz_async_endpoint")
    if mod_name == "tests.fuzz.transport_and_chaos.fuzz_async_evil_server":
        return importlib.import_module("tests.fuzz.transport_and_chaos.fuzz_async_evil_server")
    if mod_name == "tests.fuzz.endpoints_and_routing.fuzz_async_pagination_and_retry":
        return importlib.import_module("tests.fuzz.endpoints_and_routing.fuzz_async_pagination_and_retry")
    if mod_name == "tests.fuzz.endpoints_and_routing.fuzz_openapi_routes_and_mock_parity":
        return importlib.import_module("tests.fuzz.endpoints_and_routing.fuzz_openapi_routes_and_mock_parity")
    if mod_name == "tests.fuzz.webhooks_and_telemetry.fuzz_version_and_exports":
        return importlib.import_module("tests.fuzz.webhooks_and_telemetry.fuzz_version_and_exports")
    if mod_name == "tests.fuzz.webhooks_and_telemetry.fuzz_telemetry":
        return importlib.import_module("tests.fuzz.webhooks_and_telemetry.fuzz_telemetry")
    if mod_name == "tests.fuzz.security_and_guardrails.fuzz_transport_security":
        return importlib.import_module("tests.fuzz.security_and_guardrails.fuzz_transport_security")
    if mod_name == "tests.fuzz.security_and_guardrails.fuzz_multipart_and_filesystem":
        return importlib.import_module("tests.fuzz.security_and_guardrails.fuzz_multipart_and_filesystem")
    msg = f"Unexpected fuzz module: {mod_name!r}"
    raise ImportError(msg)


def test_async_fuzz_targets_smoke() -> None:
    """Verify the async Atheris fuzz targets import and process sample inputs cleanly."""
    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    async_modules = (
        "tests.fuzz.clients.fuzz_async_client",
        "tests.fuzz.endpoints_and_routing.fuzz_async_endpoint",
        "tests.fuzz.transport_and_chaos.fuzz_async_evil_server",
        "tests.fuzz.endpoints_and_routing.fuzz_async_pagination_and_retry",
        "tests.fuzz.endpoints_and_routing.fuzz_openapi_routes_and_mock_parity",
    )
    loaded_mods: list[Any] = []
    try:
        for mod_name in async_modules:
            sys.modules.pop(mod_name, None)
            fuzz_mod = _import_fuzz_target(mod_name)
            loaded_mods.append(fuzz_mod)

            fuzz_mod.TestOneInput(b"short")
            for mode_byte in (0, 1, 2):
                fuzz_mod.TestOneInput(bytes([mode_byte]) + b"fuzz_payload_padding_0123456789")
    finally:
        logging.disable(prev_disable)
        for fuzz_mod in loaded_mods:
            sync_obj = getattr(fuzz_mod, "_sync_client", None)
            if sync_obj is not None:
                sync_obj.close()
            loop = getattr(fuzz_mod, "_loop", None)
            for client_attr in ("_base_async_client", "_aclient", "_async_client"):
                client_obj = getattr(fuzz_mod, client_attr, None)
                if client_obj is not None and loop is not None and not loop.is_closed():
                    loop.run_until_complete(client_obj.aclose())
            if loop is not None and not loop.is_closed():
                loop.close()
        for mod_name in async_modules:
            sys.modules.pop(mod_name, None)
        if injected:
            sys.modules.pop("atheris", None)
    assert logging.root.manager.disable == prev_disable


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
            '2026-11-17T11:00:12.5919245Z "https://u:p@api.mailjet.com/v3" # Uses: 50',  # pragma: allowlist secret
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
    prev_disable = logging.root.manager.disable
    mod_name = "tests.fuzz.webhooks_and_telemetry.fuzz_webhooks"
    try:
        sys.modules.pop(mod_name, None)
        fuzz_mod = importlib.import_module("tests.fuzz.webhooks_and_telemetry.fuzz_webhooks")
        fuzz_mod.TestOneInput(b"short")
        for mode_byte in (0, 1, 2):
            fuzz_mod.TestOneInput(bytes([mode_byte]) + b"webhook_payload_fuzz_seed_bytes_12345678")
    finally:
        logging.disable(prev_disable)
        sys.modules.pop(mod_name, None)
        if injected:
            sys.modules.pop("atheris", None)
    assert logging.root.manager.disable == prev_disable


def test_new_core_business_logic_fuzz_targets_smoke() -> None:
    """Verify newly added version, telemetry, transport-security, and filesystem fuzz targets run cleanly."""
    _, injected = _ensure_atheris_stub()
    prev_disable = logging.root.manager.disable
    sync_modules = (
        "tests.fuzz.webhooks_and_telemetry.fuzz_version_and_exports",
        "tests.fuzz.webhooks_and_telemetry.fuzz_telemetry",
        "tests.fuzz.security_and_guardrails.fuzz_transport_security",
        "tests.fuzz.security_and_guardrails.fuzz_multipart_and_filesystem",
    )
    try:
        for mod_name in sync_modules:
            sys.modules.pop(mod_name, None)
            fuzz_mod = _import_fuzz_target(mod_name)
            fuzz_mod.TestOneInput(b"short")
            for mode_byte in (0, 1, 2):
                fuzz_mod.TestOneInput(bytes([mode_byte]) + b"core_business_logic_fuzz_seed_bytes_012345")
    finally:
        logging.disable(prev_disable)
        for mod_name in sync_modules:
            sys.modules.pop(mod_name, None)
        if injected:
            sys.modules.pop("atheris", None)
    assert logging.root.manager.disable == prev_disable


def test_discover_fuzzer_logs_supports_nested_scope_subdirectories(tmp_path: Path) -> None:
    """Harvester discover_fuzzer_logs locates logs for both flat and scope-nested fuzz_*.py scripts."""
    import scripts.harvest_fuzzer_dict as harvester  # ruff: ignore[import-outside-top-level]

    fuzz_dir = tmp_path / "fuzz"
    scope_dir = fuzz_dir / "clients"
    scope_dir.mkdir(parents=True)
    (fuzz_dir / "fuzz_flat.py").write_text("def TestOneInput(d): pass\n", encoding="utf-8")
    (scope_dir / "fuzz_scoped.py").write_text("def TestOneInput(d): pass\n", encoding="utf-8")

    logs_dir = tmp_path / "logs"
    for name in ("fuzz_flat", "fuzz_scoped"):
        target_log_dir = logs_dir / name
        target_log_dir.mkdir(parents=True)
        (target_log_dir / "fuzz_output.log").write_text("", encoding="utf-8")

    discovered = harvester.discover_fuzzer_logs(fuzz_dir=fuzz_dir, logs_dir=logs_dir)
    assert {p.parent.name for p in discovered} == {"fuzz_flat", "fuzz_scoped"}
