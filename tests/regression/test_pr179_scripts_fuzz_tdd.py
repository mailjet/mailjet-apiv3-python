"""Strict TDD regression tests for PR #179 Issues #4, #6, #9d, and #14f."""

from __future__ import annotations

import ast
import contextlib
import importlib.util
import io
import json
import string
import sys
import types
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any
from unittest.mock import patch

import pytest
import requests


REPO_ROOT = Path(__file__).resolve().parents[2]
FUZZER_DICT_PATH = REPO_ROOT / "tests" / "fuzz" / "fuzzer.dict"


def _load_script(script_name: str, module_alias: str) -> Any:
    """Load a script from scripts/ via importlib without relying on sys.path."""
    script_path = REPO_ROOT / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_alias, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_alias] = module
    spec.loader.exec_module(module)
    return module


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
    stub.instrument_imports = lambda **_kwargs: contextlib.nullcontext()  # type: ignore[attr-defined]
    stub.instrument_all = lambda: None  # type: ignore[attr-defined]
    stub.Setup = lambda *_args, **_kwargs: None  # type: ignore[attr-defined]
    stub.Fuzz = lambda: None  # type: ignore[attr-defined]
    sys.modules["atheris"] = stub
    return stub, True


def _load_fuzz_module(filename: str, alias: str) -> Any:
    fuzz_path = REPO_ROOT / "tests" / "fuzz" / filename
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


def _libfuzzer_parse_one_dict_entry(line: str) -> bytes | None:
    """Strict Python implementation of LLVM libFuzzer ParseOneDictionaryEntry grammar."""
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    first_quote = stripped.find('"')
    last_quote = stripped.rfind('"')
    if first_quote == -1 or last_quote <= first_quote or last_quote != len(stripped) - 1:
        return None
    if first_quote > 0:
        prefix = stripped[:first_quote]
        if not prefix.endswith("=") or len(prefix) < 2:
            return None
        key_name = prefix[:-1]
        if any(ch.isspace() or ch in {'"', "\\"} for ch in key_name):
            return None

    inner = stripped[first_quote + 1 : last_quote]
    out = bytearray()
    i = 0
    hex_chars = frozenset(string.hexdigits)
    while i < len(inner):
        ch = inner[i]
        if ch == '"':
            return None
        if ch == "\\":
            if i + 1 >= len(inner):
                return None
            nxt = inner[i + 1]
            if nxt in {'"', "\\"}:
                out.append(ord(nxt))
                i += 2
            elif nxt == "x":
                if i + 3 >= len(inner) or inner[i + 2] not in hex_chars or inner[i + 3] not in hex_chars:
                    return None
                out.append(int(inner[i + 2 : i + 4], 16))
                i += 4
            else:
                return None
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    return bytes(out) if out else None


# ==========================================
# Issue #4 — libFuzzer .dict & Harvester Grammar
# ==========================================


def test_fuzzer_dict_conforms_to_libfuzzer_parse_one_dictionary_entry() -> None:
    """PR #179 #4: Every non-empty non-comment line in tests/fuzz/fuzzer.dict must satisfy libFuzzer grammar."""
    lines = FUZZER_DICT_PATH.read_text(encoding="utf-8").splitlines()
    assert lines, "tests/fuzz/fuzzer.dict must not be empty"

    invalid_lines: list[tuple[int, str]] = []
    for line_no, raw_line in enumerate(lines, start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        parsed = _libfuzzer_parse_one_dict_entry(raw_line)
        if parsed is None or not (1 <= len(parsed) <= 128):
            invalid_lines.append((line_no, raw_line))

    assert invalid_lines == [], f"Invalid libFuzzer .dict entries found: {invalid_lines[:5]}"


def test_parse_dict_line_rejects_unescaped_quotes_and_invalid_escapes() -> None:
    """PR #179 #4: harvest_fuzzer_dict.parse_dict_line rejects unescaped inner quotes and invalid escapes."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_issue4")

    assert harvester.parse_dict_line('"<!DCD?+>""') is None
    assert harvester.parse_dict_line('"foo"bar"') is None
    assert harvester.parse_dict_line('"bad\\z"') is None
    assert harvester.parse_dict_line('"bad\\xZZ"') is None
    assert harvester.parse_dict_line('"bad\\x1"') is None
    assert harvester.parse_dict_line('"trailing\\"') is None
    assert harvester.parse_dict_line('""') is None

    assert harvester.parse_dict_line('kw="hello\\x20world"') == b"hello world"
    assert harvester.parse_dict_line('"<!DCD?+>\\""') == b'<!DCD?+>"'
    assert harvester.parse_dict_line('"C:\\\\Windows"') == b"C:\\Windows"


def test_merge_dictionary_canonicalizes_existing_lines(tmp_path: Path) -> None:
    """PR #179 #4: merge_dictionary canonicalizes existing entries via parse_dict_line + format_dict_entry."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_merge")
    dict_file = tmp_path / "fuzzer.dict"
    dict_file.write_text(
        'alias_key="hello\\x20world"\n"\\x66\\x6f\\x6f"\n"<!DCD?+>""\n# ignored comment\n',
        encoding="utf-8",
    )

    _, added_count, merged = harvester.merge_dictionary(
        dict_file,
        Counter({b"hello world": 4, b"fresh_token": 2}),
        write=True,
    )

    assert added_count == 1
    assert '"hello world"' in merged
    assert '"foo"' in merged
    assert '"fresh_token"' in merged
    assert 'alias_key="hello\\x20world"' not in merged
    assert '"\\x66\\x6f\\x6f"' not in merged
    assert '"<!DCD?+>""' not in merged
    assert dict_file.read_text(encoding="utf-8").splitlines() == merged


# ==========================================
# Issue #9d — harvest_fuzzer_dict.py DoS, Symlinks, Filename & DRY
# ==========================================


def test_collect_from_zip_enforces_member_and_uncompressed_byte_caps(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #9d: _collect_from_zip rejects excessive zip members and decompression bombs (CWE-409)."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_zip")

    assert harvester.MAX_ZIP_MEMBERS <= 512
    assert harvester.MAX_UNCOMPRESSED_BYTES <= 256 * 1024 * 1024

    many_members_buf = io.BytesIO()
    with zipfile.ZipFile(many_members_buf, "w") as zf:
        for idx in range(harvester.MAX_ZIP_MEMBERS + 1):
            zf.writestr(f"log_{idx:04d}.txt", "")
    with pytest.raises(ValueError, match="member"):
        harvester._collect_from_zip(many_members_buf.getvalue())

    bomb_buf = io.BytesIO()
    with zipfile.ZipFile(bomb_buf, "w", compression=zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("bomb.log", b"A" * 4096)
    monkeypatch.setattr(harvester, "MAX_UNCOMPRESSED_BYTES", 1024)
    with pytest.raises(ValueError, match="uncompressed"):
        harvester._collect_from_zip(bomb_buf.getvalue())


def test_github_https_get_enforces_bounded_download_limit(monkeypatch: pytest.MonkeyPatch) -> None:
    """PR #179 #9d: _github_https_get streams responses and enforces MAX_DOWNLOAD_BYTES cap."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_http_cap")
    assert harvester.MAX_DOWNLOAD_BYTES <= 256 * 1024 * 1024
    monkeypatch.setattr(harvester, "MAX_DOWNLOAD_BYTES", 1024)

    class _StreamingResp:
        def __init__(self, chunks: list[bytes], headers: dict[str, str] | None = None) -> None:
            self.status_code = 200
            self.headers = headers or {"Content-Type": "application/octet-stream"}
            self._chunks = chunks
            self.closed = False
            self.read_chunks = 0

        def iter_content(self, chunk_size: int = 65536) -> Any:
            _ = chunk_size
            for chunk in self._chunks:
                self.read_chunks += 1
                yield chunk

        def close(self) -> None:
            self.closed = True

    streaming_resp = _StreamingResp([b"X" * 600, b"Y" * 600, b"Z" * 600])
    with patch.object(requests, "get", return_value=streaming_resp):
        with pytest.raises(ValueError, match="exceeds maximum"):
            harvester._github_https_get(
                "https://api.github.com/repos/mailjet/mailjet-apiv3-python/actions/runs/1/logs",
                None,
            )
    assert streaming_resp.closed is True
    assert streaming_resp.read_chunks == 2

    header_resp = _StreamingResp([], headers={"Content-Length": "2048"})
    with patch.object(requests, "get", return_value=header_resp):
        with pytest.raises(ValueError, match="exceeds maximum"):
            harvester._github_https_get(
                "https://api.github.com/repos/mailjet/mailjet-apiv3-python/actions/runs/2/logs",
                None,
            )
    assert header_resp.closed is True


def test_collect_from_path_skips_symlinks(tmp_path: Path) -> None:
    """PR #179 #9d: collect_from_path ignores symlink files and directory symlink children."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_symlink")

    outside = tmp_path / "outside_secret.log"
    outside.write_text(
        '###### Recommended dictionary. ######\n"symlink_leak_token" # Uses: 99\n'
        "###### End of recommended dictionary. ######\n",
        encoding="utf-8",
    )

    logs_dir = tmp_path / "logs"
    logs_dir.mkdir()
    real_log = logs_dir / "real.log"
    real_log.write_text(
        '###### Recommended dictionary. ######\n"real_log_token" # Uses: 5\n'
        "###### End of recommended dictionary. ######\n",
        encoding="utf-8",
    )
    symlink_log = logs_dir / "escape.log"
    symlink_log.symlink_to(outside)

    dir_counts = harvester.collect_from_path(logs_dir)
    assert dir_counts[b"real_log_token"] == 5
    assert b"symlink_leak_token" not in dir_counts

    direct_counts = harvester.collect_from_path(symlink_log)
    assert direct_counts == Counter()


def test_discover_and_zip_collect_fuzzer_output_log(tmp_path: Path) -> None:
    """PR #179 #9d: discover_fuzzer_logs and zip collection support fuzzer_output.log as well as .log/.txt."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_fuzzer_dict_fuzzer_output")

    fuzz_dir = tmp_path / "fuzz"
    fuzz_dir.mkdir()
    (fuzz_dir / "fuzz_demo.py").write_text("def TestOneInput(d): pass\n", encoding="utf-8")

    logs_dir = tmp_path / "logs"
    target_dir = logs_dir / "fuzz_demo"
    target_dir.mkdir(parents=True)
    log_file = target_dir / "fuzzer_output.log"
    log_file.write_text(
        '###### Recommended dictionary. ######\n"fuzzer_output_tok" # Uses: 3\n'
        "###### End of recommended dictionary. ######\n",
        encoding="utf-8",
    )

    discovered = harvester.discover_fuzzer_logs(fuzz_dir=fuzz_dir, logs_dir=logs_dir)
    assert discovered == [log_file]

    zip_buf = io.BytesIO()
    with zipfile.ZipFile(zip_buf, "w") as zf:
        zf.writestr("nested/fuzzer_output.log", log_file.read_text(encoding="utf-8"))
        zf.writestr(
            "nested/extra.txt",
            '###### Recommended dictionary. ######\n"txt_tok" # Uses: 2\n###### End of recommended dictionary. ######\n',
        )
    zip_counts = harvester._collect_from_zip(zip_buf.getvalue())
    assert zip_counts[b"fuzzer_output_tok"] == 3
    assert zip_counts[b"txt_tok"] == 2


def test_harvest_fuzzer_dict_shares_unified_unprocessed_fetch_helper() -> None:
    """PR #179 #9d: _fetch_unprocessed_runs and _fetch_unprocessed_jobs must share one unified helper (no DRY clone)."""
    script_path = REPO_ROOT / "scripts" / "harvest_fuzzer_dict.py"
    tree = ast.parse(script_path.read_text(encoding="utf-8"), filename=str(script_path))
    funcs = {node.name: node for node in tree.body if isinstance(node, ast.FunctionDef)}

    for fn_name in ("_fetch_unprocessed_runs", "_fetch_unprocessed_jobs"):
        if fn_name in funcs:
            # Must not duplicate full for-loop + _github_https_get pagination bodies.
            assert len(funcs[fn_name].body) <= 2, f"{fn_name} still duplicates fetch loop instead of delegating"

    called_helpers = {
        node.func.id
        for node in ast.walk(funcs["collect_from_github"])
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }
    if "_fetch_unprocessed_runs" in funcs:
        called_helpers |= {
            node.func.id
            for node in ast.walk(funcs["_fetch_unprocessed_runs"])
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
        }
    assert any(
        name in funcs and name not in {"_fetch_unprocessed_runs", "_fetch_unprocessed_jobs"} for name in called_helpers
    )


# ==========================================
# Issue #6 — seed_harvester.py Redaction, Safety & Cleanup
# ==========================================


def test_seed_harvester_excludes_sensitive_and_v3_send_targets(tmp_path: Path) -> None:
    """PR #179 #6: Live TARGETS must omit apikey_get, tokens_get, myprofile_get, user_get, and send_v3_post."""
    seed_harvester = _load_script("seed_harvester.py", "seed_harvester_targets")
    target_names = {t.name for t in seed_harvester.TARGETS}

    forbidden = {"apikey_get", "tokens_get", "myprofile_get", "user_get", "send_v3_post"}
    assert target_names.isdisjoint(forbidden), f"Forbidden live targets present: {target_names & forbidden}"

    writer = seed_harvester.CorpusWriter(tmp_path)
    seed_harvester.generate_synthetic_seeds(writer)
    assert writer.written_count > 0
    endpoint_seeds = list((tmp_path / "fuzz_endpoint").glob("synth_*.seed"))
    assert len(endpoint_seeds) >= 3


def test_seed_harvester_scrubs_sensitive_fields_from_live_responses(tmp_path: Path) -> None:
    """PR #179 #6: Sensitive PII/secret fields must be scrubbed from live responses before write_seed()."""
    seed_harvester = _load_script("seed_harvester.py", "seed_harvester_scrub")
    writer = seed_harvester.CorpusWriter(tmp_path)

    sensitive_payload = {
        "Count": 1,
        "Data": [
            {
                "ID": 77,
                "Email": "subscriber.real@company.org",
                "Name": "Alice RealName",
                "APIKey": "mj_live_pub_secret123",
                "SecretKey": "mj_live_priv_secret456",
                "AccessToken": "atk_live_999888",
                "Token": "tok_live_777666",
                "Bearer": "Bearer eyJhbGciOiJIUzI1NiJ9.live_jwt",
            }
        ],
    }

    fake_resp = requests.Response()
    fake_resp.status_code = 200
    fake_resp._content = json.dumps(sensitive_payload).encode("utf-8")
    fake_resp.headers["Content-Type"] = "application/json"

    with requests.Session() as session, patch.object(session, "request", return_value=fake_resp):
        seed_harvester.harvest_live_static_targets(session, writer, timeout=5.0)

    seed_files = list(tmp_path.rglob("*.seed"))
    assert seed_files, "Expected live static target seeds to be written"
    leaked_markers = (
        "subscriber.real@company.org",
        "Alice RealName",
        "mj_live_pub_secret123",
        "mj_live_priv_secret456",
        "atk_live_999888",
        "tok_live_777666",
        "eyJhbGciOiJIUzI1NiJ9.live_jwt",
    )
    for seed_file in seed_files:
        text = seed_file.read_text(encoding="utf-8", errors="replace")
        for marker in leaked_markers:
            assert marker not in text, f"Sensitive marker {marker!r} leaked into {seed_file}"


def test_seed_harvester_corpus_map_has_no_dead_template_keys_and_includes_fuzz_webhooks(tmp_path: Path) -> None:
    """PR #179 #6: CORPUS_MAP removes dead lifecycle_template_* keys and all_fdp_fuzzers includes fuzz_webhooks."""
    seed_harvester = _load_script("seed_harvester.py", "seed_harvester_corpus_map")
    valid_targets = {t.name for t in seed_harvester.TARGETS} | {
        "lifecycle_contact_create",
        "lifecycle_contact_get",
        "lifecycle_contact_update",
        "lifecycle_contact_delete",
    }

    for fuzzer_name, mapped in seed_harvester.CORPUS_MAP.items():
        assert "lifecycle_template_create" not in mapped
        assert "lifecycle_template_content" not in mapped
        dead = set(mapped) - valid_targets
        assert not dead, f"Dead target keys in CORPUS_MAP[{fuzzer_name!r}]: {dead}"

    writer = seed_harvester.CorpusWriter(tmp_path)
    seed_harvester.generate_synthetic_seeds(writer)
    webhook_seeds = list((tmp_path / "fuzz_webhooks").glob("*.seed"))
    assert webhook_seeds, "fuzz_webhooks must be included in all_fdp_fuzzers"


def test_seed_harvester_session_sets_explicit_user_agent(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """PR #179 #6: Live harvest session sets an explicit User-Agent and preserves request timeouts."""
    seed_harvester = _load_script("seed_harvester.py", "seed_harvester_ua")
    monkeypatch.setenv("MJ_APIKEY_PUBLIC", "pub_dummy_123")
    monkeypatch.setenv("MJ_APIKEY_PRIVATE", "priv_dummy_456")

    observed_headers: list[dict[str, str]] = []
    observed_timeouts: list[float] = []

    def _fake_request(self: requests.Session, method: str, url: str, **kwargs: Any) -> requests.Response:
        _ = (method, url)
        observed_headers.append({str(k): str(v) for k, v in self.headers.items()})
        observed_timeouts.append(float(kwargs["timeout"]))
        resp = requests.Response()
        resp.status_code = 200
        resp._content = b'{"Count": 0, "Data": []}'
        return resp

    with patch.object(requests.Session, "request", _fake_request):
        seed_harvester.harvest_seeds(mode="live", output_dir=tmp_path, timeout=7.5)

    assert observed_headers, "Expected live harvest requests to execute"
    ua = observed_headers[0].get("User-Agent", "")
    assert "mailjet" in ua.lower()
    assert all(t == 7.5 for t in observed_timeouts)


def test_harvest_live_crud_lifecycles_uses_v4_delete_and_independent_suppress(tmp_path: Path) -> None:
    """PR #179 #6: finally uses DELETE /v4/contacts/{id}, emits delete seed only if non-empty <400, and isolates suppress."""
    seed_harvester = _load_script("seed_harvester.py", "seed_harvester_crud")

    def _json_resp(status: int, payload: Any) -> requests.Response:
        resp = requests.Response()
        resp.status_code = status
        resp._content = json.dumps(payload).encode("utf-8") if payload is not None else b""
        return resp

    # Scenario 1: Happy path with 200 non-empty delete response
    calls_1: list[tuple[str, str]] = []
    writer_1 = seed_harvester.CorpusWriter(tmp_path / "case1")
    with requests.Session() as sess1:

        def _req1(method: str, url: str, **_kwargs: Any) -> requests.Response:
            calls_1.append((method, url))
            if method == "POST" and url.endswith("/contact"):
                return _json_resp(201, {"Data": [{"ID": 555}]})
            if method == "POST" and url.endswith("/contactslist"):
                return _json_resp(201, {"Data": [{"ID": 777}]})
            if method == "DELETE" and "/v4/contacts/555" in url:
                return _json_resp(200, {"Deleted": True})
            return _json_resp(200, {"Data": []})

        with patch.object(sess1, "request", side_effect=_req1):
            seed_harvester.harvest_live_crud_lifecycles(sess1, writer_1, timeout=5.0)

    delete_urls_1 = [u for m, u in calls_1 if m == "DELETE"]
    assert f"{seed_harvester.BASE_URL_V4}/contacts/555" in delete_urls_1
    assert f"{seed_harvester.BASE_URL_V3}/contact/555" not in delete_urls_1
    assert f"{seed_harvester.BASE_URL_V3}/contactslist/777" in delete_urls_1
    assert list((tmp_path / "case1" / "fuzz_async_endpoint").glob("*lifecycle_contact_delete*.seed"))

    # Scenario 2: Contact DELETE fails with RequestException -> contactslist DELETE must STILL execute
    calls_2: list[tuple[str, str]] = []
    writer_2 = seed_harvester.CorpusWriter(tmp_path / "case2")
    with requests.Session() as sess2:

        def _req2(method: str, url: str, **_kwargs: Any) -> requests.Response:
            calls_2.append((method, url))
            if method == "POST" and url.endswith("/contact"):
                return _json_resp(201, {"Data": [{"ID": 556}]})
            if method == "POST" and url.endswith("/contactslist"):
                return _json_resp(201, {"Data": [{"ID": 778}]})
            if method == "DELETE" and "/v4/contacts/556" in url:
                raise requests.ConnectionError("transient delete failure")
            return _json_resp(200, {"Data": []})

        with patch.object(sess2, "request", side_effect=_req2):
            seed_harvester.harvest_live_crud_lifecycles(sess2, writer_2, timeout=5.0)

    assert f"{seed_harvester.BASE_URL_V3}/contactslist/778" in [u for m, u in calls_2 if m == "DELETE"]
    assert not list((tmp_path / "case2" / "fuzz_async_endpoint").glob("*lifecycle_contact_delete*.seed"))

    # Scenario 3: Contact DELETE returns 204 empty or 404 -> no lifecycle_contact_delete seed emitted
    writer_3 = seed_harvester.CorpusWriter(tmp_path / "case3")
    with requests.Session() as sess3:

        def _req3(method: str, url: str, **_kwargs: Any) -> requests.Response:
            if method == "POST" and url.endswith("/contact"):
                return _json_resp(201, {"Data": [{"ID": 557}]})
            if method == "POST" and url.endswith("/contactslist"):
                return _json_resp(201, {"Data": [{"ID": 779}]})
            if method == "DELETE" and "/v4/contacts/557" in url:
                return _json_resp(204, None)
            return _json_resp(200, {"Data": []})

        with patch.object(sess3, "request", side_effect=_req3):
            seed_harvester.harvest_live_crud_lifecycles(sess3, writer_3, timeout=5.0)

    assert not list((tmp_path / "case3" / "fuzz_async_endpoint").glob("*lifecycle_contact_delete*.seed"))


# ==========================================
# Issue #14f — Fuzz Target Fixes
# ==========================================


def test_fuzz_client_uses_real_attach_methods_gates_5mb_and_reuses_client() -> None:
    """PR #179 #14f: fuzz_client calls attach_file/attach_inline, gates >5MB branch to ~1%, and reuses Client."""
    src = (REPO_ROOT / "tests" / "fuzz" / "fuzz_client.py").read_text(encoding="utf-8")
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
    alias = "fuzz_client_under_test"
    try:
        mod = _load_fuzz_module("fuzz_client.py", alias)
        for seed in (b"short", bytes([3]) + b"sender@example.com_fuzz_payload_padding_0123456789"):
            mod.TestOneInput(seed)
    finally:
        mod_obj = sys.modules.pop(alias, None)
        if mod_obj is not None and getattr(mod_obj, "_base_client", None) is not None:
            mod_obj._base_client.close()
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_builder_seeds_example_com_and_smoke() -> None:
    """PR #179 #14f: fuzz_builder seeds @example.com senders and runs clean smoke passes without AttributeError traps."""
    src = (REPO_ROOT / "tests" / "fuzz" / "fuzz_builder.py").read_text(encoding="utf-8")
    assert "@example.com" in src

    _, injected = _ensure_atheris_stub()
    alias = "fuzz_builder_under_test"
    try:
        mod = _load_fuzz_module("fuzz_builder.py", alias)
        mod.TestOneInput(b"short")
        for b0 in range(10):
            mod.TestOneInput(bytes([b0]) + b"fuzz_builder_padding_0123456789abcdef")
    finally:
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_async_client_reraises_unexpected_gather_exceptions() -> None:
    """PR #179 #14f: fuzz_async_client must inspect gather results and re-raise unexpected exceptions."""
    _, injected = _ensure_atheris_stub()
    alias = "fuzz_async_client_under_test"
    mod: Any = None
    try:
        mod = _load_fuzz_module("fuzz_async_client.py", alias)
        if mod._base_async_client is None:
            pytest.skip("httpx2 not installed")

        async def _boom(*_args: Any, **_kwargs: Any) -> Any:
            raise KeyError("unexpected gather crash")

        # Mode 3 triggers asyncio.gather when ConsumeIntInRange(0, 3) == 3 (byte 0 % 4 == 3).
        with patch.object(type(mod._base_async_client.contact), "get", side_effect=_boom):
            with pytest.raises(RuntimeError, match="UNHANDLED CRASH"):
                mod.TestOneInput(bytes([3]) + b"fuzz_async_gather_payload_1234567890")
    finally:
        if mod is not None:
            _cleanup_async_fuzz_module(mod, alias)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_async_evil_server_does_not_swallow_raw_httpx2_or_json_errors() -> None:
    """PR #179 #14f: fuzz_async_evil_server uses contextlib.aclosing and does not swallow raw httpx2/JSON errors."""
    src = (REPO_ROOT / "tests" / "fuzz" / "fuzz_async_evil_server.py").read_text(encoding="utf-8")
    assert "aclosing" in src

    _, injected = _ensure_atheris_stub()
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
        if mod is not None:
            _cleanup_async_fuzz_module(mod, alias)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_webhooks_checks_valid_hmac_roundtrip_and_empty_secret() -> None:
    """PR #179 #14f: fuzz_webhooks asserts valid HMAC-SHA256 returns True (false-rejection check) & handles empty secret."""
    _, injected = _ensure_atheris_stub()
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
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)


def test_fuzz_jitter_retry_asserts_math_isfinite() -> None:
    """PR #179 #14f: fuzz_jitter_retry rejects non-finite NaN/inf delays on compute_retry_delay & parse_retry_after_http_date."""
    _, injected = _ensure_atheris_stub()
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
        sys.modules.pop(alias, None)
        if injected:
            sys.modules.pop("atheris", None)
