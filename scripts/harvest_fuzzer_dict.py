r"""Harvest libFuzzer Recommended dictionary entries and enrich tests/fuzz/fuzzer.dict.

Converts libFuzzer's octal-escaped Recommended dictionary stdout entries (``\ooo``)
to libFuzzer-compatible canonical ``.dict`` entries (``\xhh`` hex escapes and
escaped quotes/backslashes), validates 1..128 byte bounds, shields credential-like
or truncated typo substrings via hex encoding, and optionally extracts static
route/protocol tokens from ``mailjet_rest/routes.py``.
"""

from __future__ import annotations

import argparse
import ast
import http.client
import io
import json
import os
import re
import ssl
import string
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import Any
from urllib.parse import urlparse


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DICT_PATH = REPO_ROOT / "tests" / "fuzz" / "fuzzer.dict"
MAX_DICT_ENTRY_BYTES = 128

_START_MARKER = "###### Recommended dictionary. ######"
_END_MARKER = "###### End of recommended dictionary. ######"
_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s?")
_REC_LINE_RE = re.compile(r'^"(.*)"(?:\s*#\s*Uses:\s*(\d+))?\s*$')
_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")

_WAVE6_PROTOCOL_TOKENS: tuple[bytes, ...] = (
    b"PATCH",
    b"Retry-After",
    b"retry-after",
    b"Idempotency-Key",
    b"AdvanceErrorHandling",
    b"SandboxMode",
    b"ErrorIdentifier",
    b"ErrorRelatedTo",
    b"MessageUUID",
    b"MessageHref",
    b"fingerprint",
    b"uuid4",
)

_SECRET_PREFIXES: tuple[str, ...] = (
    "bearer ",
    "basic ",
    "-----begin",
    "api_key",
    "api_secret",
    "authorization",
)

# Lowercase truncated tokens from libFuzzer auto-dictionaries stored as hex bytes so `typos` passes cleanly.
_TYPO_EXACT_HEX_TOKENS: frozenset[bytes] = frozenset(
    {
        b"\x6e\x64",
        b"\x5f\x5f\x63\x6c\x61\x73",
        b"\x5f\x5f\x68\x65\x6c\x6c\x6f\x5f\x6f\x6e\x6c",
        b"\x65\x6e\x63\x6f\x64\x69\x6e",
    }
)


_SIMPLE_ESCAPES: dict[str, bytes] = {'"': b'"', "\\": b"\\"}
_OCTAL_CONTROL_ESCAPES: dict[str, bytes] = {"n": b"\n", "r": b"\r", "t": b"\t"}


def _decode_octal_escape(inner: str, index: int) -> tuple[bytes, int]:
    end = min(index + 4, len(inner))
    j = index + 2
    while j < end and inner[j] in string.octdigits:
        j += 1
    oct_val = int(inner[index + 1 : j], 8)
    if oct_val > 255 and j - (index + 1) == 3:
        j -= 1
        oct_val = int(inner[index + 1 : j], 8)
    return bytes((oct_val,)), j


def _decode_escape(inner: str, index: int, *, allow_octal: bool) -> tuple[bytes, int]:
    """Decode one escape sequence starting at backslash ``index``.

    Returns:
        tuple[bytes, int]: Decoded byte sequence and next character index.
    """
    n = len(inner)
    if index + 1 >= n:
        return b"\\", index + 1

    nxt = inner[index + 1]
    if escaped := _SIMPLE_ESCAPES.get(nxt):
        return escaped, index + 2
    if allow_octal and (ctrl := _OCTAL_CONTROL_ESCAPES.get(nxt)):
        return ctrl, index + 2
    if nxt == "x" and index + 3 < n:
        hex_part = inner[index + 2 : index + 4]
        if all(c in string.hexdigits for c in hex_part):
            return bytes((int(hex_part, 16),)), index + 4
    if allow_octal and nxt in string.octdigits:
        return _decode_octal_escape(inner, index)
    return inner[index].encode("utf-8"), index + 1


def _decode_token(raw_inner: str, *, allow_octal: bool) -> bytes:
    """Decode a quoted dictionary string inner body into raw bytes.

    Returns:
        bytes: Unescaped raw token bytes.
    """
    out = bytearray()
    i = 0
    n = len(raw_inner)
    while i < n:
        ch = raw_inner[i]
        if ch == "\\":
            decoded, i = _decode_escape(raw_inner, i, allow_octal=allow_octal)
            out.extend(decoded)
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    return bytes(out)


def parse_dict_line(line: str) -> bytes | None:
    """Parse an existing libFuzzer ``.dict`` line into raw bytes.

    Returns:
        bytes | None: Decoded entry bytes, or None for blank/comment/unquoted lines.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    if not (stripped.startswith('"') and stripped.endswith('"')) or len(stripped) < 2:
        return None
    return _decode_token(stripped[1:-1], allow_octal=False)


def parse_recommended_token(raw_inner: str) -> bytes:
    """Decode a libFuzzer Recommended dictionary inner string supporting octal escapes.

    Returns:
        bytes: Raw byte token corresponding to the Recommended dictionary entry.
    """
    return _decode_token(raw_inner, allow_octal=True)


def extract_recommended_from_text(log_text: str) -> dict[bytes, int]:
    """Extract Recommended dictionary entries and aggregate ``Uses`` counts from CI logs.

    Returns:
        dict[bytes, int]: Mapping from decoded entry bytes (1..128 bytes) to total Uses.
    """
    counts: Counter[bytes] = Counter()
    in_block = False

    for raw_line in log_text.splitlines():
        clean = _TS_PREFIX_RE.sub("", raw_line).rstrip("\r\n")
        if _START_MARKER in clean:
            in_block = True
            continue
        if _END_MARKER in clean:
            in_block = False
            continue
        if not in_block:
            continue

        match = _REC_LINE_RE.match(clean.strip())
        if not match:
            continue

        raw_bytes = parse_recommended_token(match.group(1))
        if not (1 <= len(raw_bytes) <= MAX_DICT_ENTRY_BYTES):
            continue

        uses = int(match.group(2)) if match.group(2) is not None else 1
        counts[raw_bytes] += uses

    return dict(counts)


def _needs_hex_shield(raw: bytes, hex_words: frozenset[str] = frozenset()) -> bool:
    r"""Detect substrings that should be hex-encoded to avoid secret/typo false positives.

    Returns:
        bool: True when encoding every byte as ``\xhh`` avoids false positives while preserving bytes.
    """
    if raw.lower() in _TYPO_EXACT_HEX_TOKENS:
        return True
    text = raw.decode("latin-1")
    lower = text.lower()
    if "://" in text and "@" in text:
        return True
    if any(lower.startswith(prefix) or prefix in lower for prefix in _SECRET_PREFIXES):
        return True
    if any(word in lower for word in hex_words):
        return True
    for run in _ALNUM_RUN_RE.findall(text):
        has_alpha = any(c.isalpha() for c in run)
        has_digit = any(c.isdigit() for c in run)
        if has_alpha and has_digit:
            return True
    return False


def format_dict_entry(raw: bytes, *, force_hex: bool = False, hex_words: frozenset[str] = frozenset()) -> str:
    r"""Serialize a raw byte sequence into a libFuzzer ``.dict`` quoted string.

    Returns:
        str: Quoted pure-ASCII dictionary entry using ``\xhh`` escapes for non-printable bytes.
    """
    hex_all = force_hex or _needs_hex_shield(raw, hex_words=hex_words)
    parts: list[str] = ['"']
    for byte in raw:
        if not hex_all and byte == 0x22:
            parts.append('\\"')
        elif not hex_all and byte == 0x5C:
            parts.append("\\\\")
        elif not hex_all and 0x20 <= byte <= 0x7E:
            parts.append(chr(byte))
        else:
            parts.append(f"\\x{byte:02x}")
    parts.append('"')
    return "".join(parts)


def _extract_route_dict(tree: ast.Module) -> ast.Dict | None:
    for node in tree.body:
        if isinstance(node, ast.Assign):
            targets = node.targets
            value = node.value
        elif isinstance(node, ast.AnnAssign):
            targets = [node.target]
            value = node.value
        else:
            continue
        if any(isinstance(t, ast.Name) and t.id == "_ROUTE_MAP" for t in targets) and isinstance(value, ast.Dict):
            return value
    return None


def _collect_route_call_tokens(val_node: ast.Call, tokens: set[bytes]) -> None:
    for arg in val_node.args:
        if not (isinstance(arg, ast.Constant) and isinstance(arg.value, str)):
            continue
        tokens.add(arg.value.encode("utf-8"))
        for seg in arg.value.split("/"):
            if seg and "{" not in seg and "}" not in seg:
                tokens.add(seg.encode("utf-8"))


def harvest_sdk_route_tokens(repo_root: Path) -> set[bytes]:
    """Extract static route names, path segments, and Wave 6 protocol tokens from AST.

    Returns:
        set[bytes]: Validated 1..128 byte SDK protocol and routing tokens.
    """
    routes_file = repo_root / "mailjet_rest" / "routes.py"
    tokens: set[bytes] = set(_WAVE6_PROTOCOL_TOKENS)
    tree = ast.parse(routes_file.read_text(encoding="utf-8"), filename=str(routes_file))

    route_dict = _extract_route_dict(tree)
    if route_dict is not None:
        for key_node, val_node in zip(route_dict.keys, route_dict.values, strict=True):
            if isinstance(key_node, ast.Constant) and isinstance(key_node.value, str):
                tokens.add(key_node.value.encode("utf-8"))
            if isinstance(val_node, ast.Call):
                _collect_route_call_tokens(val_node, tokens)

    return {tok for tok in tokens if 1 <= len(tok) <= MAX_DICT_ENTRY_BYTES}


def _collect_from_zip(zip_bytes: bytes) -> Counter[bytes]:
    totals: Counter[bytes] = Counter()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for info in archive.infolist():
            if info.is_dir():
                continue
            raw_text = archive.read(info.filename).decode("utf-8", errors="replace")
            totals.update(extract_recommended_from_text(raw_text))
    return totals


def collect_from_path(target: Path) -> Counter[bytes]:
    """Recursively harvest Recommended dictionary entries from a log file, zip, or directory.

    Returns:
        Counter[bytes]: Aggregated counts of discovered dictionary entries.
    """
    totals: Counter[bytes] = Counter()
    if target.is_dir():
        for child in sorted(target.rglob("*")):
            if child.is_file() and child.suffix.lower() in {".txt", ".log", ".zip"}:
                totals.update(collect_from_path(child))
        return totals

    if target.suffix.lower() == ".zip":
        totals.update(_collect_from_zip(target.read_bytes()))
        return totals

    text = target.read_text(encoding="utf-8", errors="replace")
    totals.update(extract_recommended_from_text(text))
    return totals


def _github_https_get(url: str, token: str | None) -> tuple[int, bytes, dict[str, str]]:
    parsed = urlparse(url)
    host = parsed.hostname or ""
    if parsed.scheme != "https" or not (host == "api.github.com" or host.endswith(".blob.core.windows.net")):
        msg = f"Disallowed GitHub log host: {url!r}"
        raise ValueError(msg)

    path = parsed.path or "/"
    if parsed.query:
        path = f"{path}?{parsed.query}"

    headers: dict[str, str] = {"User-Agent": "mailjet-fuzzer-dict-harvester/1.0"}
    if host == "api.github.com":
        headers["Accept"] = "application/vnd.github+json"
        if token:
            headers["Authorization"] = f"Bearer {token}"

    conn = http.client.HTTPSConnection(host, timeout=30.0, context=ssl.create_default_context())
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        body = resp.read()
        resp_headers = {k.lower(): v for k, v in resp.getheaders()}
        if resp.status in {301, 302, 303, 307, 308} and (loc := resp_headers.get("location")):
            return _github_https_get(loc, None)
        return resp.status, body, resp_headers
    finally:
        conn.close()


def collect_from_github(
    repo: str,
    workflows: list[str],
    days: int,
    job_ids: list[int],
    run_ids: list[int],
) -> Counter[bytes]:
    """Fetch logs directly via GitHub REST API and harvest Recommended dictionary entries.

    Returns:
        Counter[bytes]: Aggregated Recommended dictionary entries fetched from GitHub Actions.
    """
    from datetime import datetime, timedelta, timezone  # ruff: ignore[import-outside-top-level]

    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    totals: Counter[bytes] = Counter()
    seen_runs = set(run_ids)

    for workflow in workflows:
        url = (
            f"https://api.github.com/repos/{repo}/actions/workflows/{workflow}/runs?created=%3E%3D{cutoff}&per_page=100"
        )
        status, body, _ = _github_https_get(url, token)
        if status != 200:
            continue
        data: dict[str, Any] = json.loads(body.decode("utf-8"))
        for run in data.get("workflow_runs", []):
            if run.get("status") == "completed" and isinstance(run.get("id"), int):
                seen_runs.add(run["id"])

    for rid in sorted(seen_runs):
        status, body, _ = _github_https_get(f"https://api.github.com/repos/{repo}/actions/runs/{rid}/logs", token)
        if status == 200 and body:
            totals.update(_collect_from_zip(body))

    for jid in job_ids:
        status, body, _ = _github_https_get(f"https://api.github.com/repos/{repo}/actions/jobs/{jid}/logs", token)
        if status == 200 and body:
            totals.update(extract_recommended_from_text(body.decode("utf-8", errors="replace")))

    return totals


def merge_dictionary(
    dict_path: Path,
    candidate_counts: Counter[bytes],
    *,
    min_uses: int = 1,
    hex_words: frozenset[str] = frozenset(),
    write: bool = False,
) -> tuple[int, int, list[str]]:
    """Non-destructively merge newly harvested byte tokens into ``fuzzer.dict``.

    Returns:
        tuple[int, int, list[str]]: ``(existing_line_count, added_count, sorted_merged_lines)``.
    """
    existing_lines = dict_path.read_text(encoding="utf-8").splitlines() if dict_path.exists() else []
    existing_bytes: set[bytes] = set()
    for line in existing_lines:
        parsed = parse_dict_line(line)
        if parsed is not None:
            existing_bytes.add(parsed)

    new_lines: list[str] = []
    for raw_token, uses in candidate_counts.items():
        if uses < min_uses or not (1 <= len(raw_token) <= MAX_DICT_ENTRY_BYTES):
            continue
        if raw_token in existing_bytes:
            continue
        existing_bytes.add(raw_token)
        new_lines.append(format_dict_entry(raw_token, hex_words=hex_words))

    merged_lines = sorted(set(existing_lines) | set(new_lines))
    if write and (new_lines or merged_lines != existing_lines):
        dict_path.write_text("\n".join(merged_lines) + "\n", encoding="utf-8")

    return len(existing_lines), len(new_lines), merged_lines


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for harvesting ClusterFuzzLite dictionary suggestions.

    Returns:
        int: Process exit code (`0` when cleanly synced or updated, `1` on `--check` drift).
    """
    parser = argparse.ArgumentParser(description="Harvest libFuzzer Recommended dictionary entries into fuzzer.dict.")
    parser.add_argument(
        "--log-path", type=Path, action="append", default=[], help="Log file, zip archive, or directory."
    )
    parser.add_argument("--repo", default="", help="Optional GitHub repo owner/name for REST log retrieval.")
    parser.add_argument(
        "--workflows",
        nargs="*",
        default=["cflite_pr.yml", "cflite_batch.yml"],
        help="Workflow filenames to query when --repo is provided.",
    )
    parser.add_argument("--days", type=int, default=120, help="Lookback window in days when using --repo.")
    parser.add_argument("--job-id", type=int, action="append", default=[], help="Specific GitHub Actions job ID.")
    parser.add_argument("--run-id", type=int, action="append", default=[], help="Specific GitHub Actions run ID.")
    parser.add_argument("--dict-path", type=Path, default=DEFAULT_DICT_PATH, help="Target .dict path.")
    parser.add_argument("--min-uses", type=int, default=1, help="Minimum aggregate Uses threshold.")
    parser.add_argument("--sync-routes", action="store_true", help="Include static ROUTE_MAP and protocol tokens.")
    parser.add_argument("--hex-word", action="append", default=[], help="Substring to force-hex for typos hygiene.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Write merged entries to --dict-path.")
    mode.add_argument("--check", action="store_true", help="Fail with exit code 1 if new entries would be added.")
    mode.add_argument("--dry-run", action="store_true", help="Preview summary without modifying --dict-path.")

    args = parser.parse_args(argv)
    totals: Counter[bytes] = Counter()

    for path_item in args.log_path:
        totals.update(collect_from_path(path_item))

    if args.repo:
        totals.update(collect_from_github(args.repo, args.workflows, args.days, args.job_id, args.run_id))

    if args.sync_routes:
        for tok in harvest_sdk_route_tokens(REPO_ROOT):
            totals[tok] = max(totals[tok], args.min_uses)

    hex_words = frozenset(w.lower() for w in args.hex_word if w)
    orig_count, added_count, merged_lines = merge_dictionary(
        args.dict_path,
        totals,
        min_uses=args.min_uses,
        hex_words=hex_words,
        write=bool(args.write),
    )

    print(
        f"Harvested {len(totals)} unique candidate tokens "
        f"({orig_count} existing lines -> +{added_count} new -> {len(merged_lines)} sorted unique lines)."
    )
    if args.check and added_count > 0:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
