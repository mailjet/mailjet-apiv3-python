"""Regression tests for libFuzzer fuzzer.dict grammar, harvest_fuzzer_dict.py, and seed_harvester.py."""

from __future__ import annotations

import ast
from collections import Counter
import importlib.util
import io
import json
from pathlib import Path
import string
import sys
import types
from typing import Any
from unittest.mock import patch
import zipfile

import pytest
import requests

from tests.regression.conftest import FUZZER_DICT_PATH, REPO_ROOT


def _load_script(script_name: str, module_alias: str) -> Any:
    """Load a script from scripts/ via importlib without relying on sys.path."""
    script_path = REPO_ROOT / "scripts" / script_name
    spec = importlib.util.spec_from_file_location(module_alias, script_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_alias] = module
    spec.loader.exec_module(module)
    return module


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


def test_harvest_fuzzer_dict_allows_actions_githubusercontent_redirect_without_token_leak() -> None:
    """PR #179 harvest_fuzzer_dict: allow 302 redirects to *.actions.githubusercontent.com without leaking Auth."""
    harvester = _load_script("harvest_fuzzer_dict.py", "harvest_v2_redirect")

    with pytest.raises(ValueError, match="Disallowed GitHub log URL"):
        harvester._build_validated_github_url("https://actions.githubusercontent.com/foo")
    with pytest.raises(ValueError, match="Disallowed GitHub log URL"):
        harvester._build_validated_github_url("http://results-receiver.actions.githubusercontent.com/foo")

    seen_calls: list[tuple[str, dict[str, str]]] = []
    redirect_url = "https://results-receiver.actions.githubusercontent.com/rest/runs/1/logs?sig=xyz"

    def _fake_get(url: str, *, headers: dict[str, str], **_kwargs: Any) -> Any:
        seen_calls.append((url, dict(headers)))
        if url.startswith("https://api.github.com/"):
            return types.SimpleNamespace(
                status_code=302,
                headers={"Location": redirect_url},
                content=b"",
                close=lambda: None,
            )
        return types.SimpleNamespace(
            status_code=200,
            headers={},
            content=b"zip-bytes",
            close=lambda: None,
        )

    with patch.object(harvester.requests, "get", side_effect=_fake_get):
        status, body, _ = harvester._github_https_get(
            "https://api.github.com/repos/mailjet/mailjet-apiv3-python/actions/jobs/1/logs",
            "dummy-token-for-redirect-test",
        )

    assert status == 200
    assert body == b"zip-bytes"
    assert len(seen_calls) == 2
    assert seen_calls[0][1].get("Authorization") == "Bearer dummy-token-for-redirect-test"
    assert seen_calls[1][0] == redirect_url
    assert "Authorization" not in seen_calls[1][1]


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

    pub_marker = "mj_live_pub_marker"
    priv_marker = "mj_live_priv_marker"
    token_marker = "atk_live_marker"
    tok_marker = "tok_live_marker"
    bearer_marker = "Bearer sampleHeader.sampleBody.sampleSig"

    sensitive_payload = {
        "Count": 1,
        "Data": [
            {
                "ID": 77,
                "Email": "subscriber.real@company.org",
                "Name": "Alice RealName",
                "APIKey": pub_marker,
                "SecretKey": priv_marker,
                "AccessToken": token_marker,
                "Token": tok_marker,
                "Bearer": bearer_marker,
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
        pub_marker,
        priv_marker,
        token_marker,
        tok_marker,
        bearer_marker,
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
