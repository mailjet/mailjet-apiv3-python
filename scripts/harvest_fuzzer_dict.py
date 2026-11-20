r"""Harvest libFuzzer Recommended dictionary entries and enrich tests/fuzz/fuzzer.dict.

Converts libFuzzer's octal-escaped Recommended dictionary stdout entries (`\ooo`)
to libFuzzer-compatible canonical `.dict` entries (`\xhh` hex escapes and
escaped quotes/backslashes), validates 1..128 byte bounds, shields credential-like
or truncated typo substrings via hex encoding, auto-discovers local fuzzer logs
from `tests/fuzz/<fuzzer_file_name>.py` -> `logs/<fuzzer_file_name>/fuzzer_output.log`,
and optionally extracts static route/protocol tokens from `mailjet_rest/routes.py`.
"""

from __future__ import annotations

import argparse
import ast
import importlib.util
import io
import json
import os
import re
import string
import sys
import zipfile
from collections import Counter
from pathlib import Path
from typing import TYPE_CHECKING, Any, cast
from urllib.parse import urlparse, urlunparse

import requests


if TYPE_CHECKING:
    from collections.abc import Callable, Iterable


REPO_ROOT = Path(__file__).resolve().parent.parent
DEFAULT_FUZZ_DIR = REPO_ROOT / "tests" / "fuzz"
DEFAULT_LOGS_DIR = REPO_ROOT / "logs"
DEFAULT_DICT_PATH = DEFAULT_FUZZ_DIR / "fuzzer.dict"
DEFAULT_STATE_PATH = DEFAULT_FUZZ_DIR / ".harvest_state.json"
MAX_DICT_ENTRY_BYTES = 128
MAX_ZIP_MEMBERS = 512
MAX_UNCOMPRESSED_BYTES = 256 * 1024 * 1024
MAX_DOWNLOAD_BYTES = 128 * 1024 * 1024
_DOWNLOAD_CHUNK_SIZE = 65536

_START_MARKER = "###### Recommended dictionary. ######"
_END_MARKER = "###### End of recommended dictionary. ######"
_TS_PREFIX_RE = re.compile(r"^\d{4}-\d{2}-\d{2}T[\d:.]+Z\s?")
_REC_LINE_RE = re.compile(r'^"(.*)"(?:\s*#\s*Uses:\s*(\d+))?\s*$')
_ALNUM_RUN_RE = re.compile(r"[A-Za-z0-9+/=_-]{20,}")
_REPO_SLUG_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_WORKFLOW_FILE_RE = re.compile(r"^[A-Za-z0-9_.-]+$")

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
    b"sha256=",
    b"ErrTreshold",
    b"text/csv",
    b"MockMailjetClient",
    b"messagesentstatistics",
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
        b"\x75\x2d\x69\x6d\x6f\x72\x74\x2d\x6f\x71\x74\x69\x6f\x6e\x73\xef\xbf\xbd\x62\x25",
        b"\x65\x72\x72\x74\x72\x65\x73\x68\x6f\x6c\x64",
        b"\x6c\x6f\x6e\x64",
        (
            b"\x31\x0b\x30\x09\x06\x03\x75\x04\x06\x0c\x02\x65\x73\x31\x62\x30\x40\x06\x03\x75\x04\x03\x0c\x39"
            b"\x61\x75\x74\x6f\x72\x69\x64\x61\x64\x20\x64\x65\x20\x63\x65\x72\x74\x69\x66\x69\x63\x61\x63\x69"
            b"\x6f\x6e\x20\x66\x69\x72\x6d\x61\x70\x72\x6f\x66\x65\x73\x69\x6f"
        ),
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


def _decode_escape(inner: str, index: int) -> tuple[bytes, int]:
    """Decode one Recommended dictionary escape sequence starting at backslash `index`.

    Args:
        inner (str): Quoted string interior without surrounding quotes.
        index (int): Current backslash character index.

    Returns:
        tuple[bytes, int]: Decoded byte sequence and next character index.
    """
    n = len(inner)
    if index + 1 >= n:
        return b"\\", index + 1

    nxt = inner[index + 1]
    if escaped := _SIMPLE_ESCAPES.get(nxt):
        return escaped, index + 2
    if ctrl := _OCTAL_CONTROL_ESCAPES.get(nxt):
        return ctrl, index + 2
    if nxt == "x" and index + 3 < n:
        hex_part = inner[index + 2 : index + 4]
        if all(c in string.hexdigits for c in hex_part):
            return bytes((int(hex_part, 16),)), index + 4
    if nxt in string.octdigits:
        return _decode_octal_escape(inner, index)
    return inner[index].encode("utf-8"), index + 1


def _decode_token(raw_inner: str) -> bytes:
    """Decode a Recommended dictionary string inner body into raw bytes.

    Args:
        raw_inner (str): Quoted dictionary entry interior.

    Returns:
        bytes: Unescaped raw token bytes.
    """
    out = bytearray()
    i = 0
    n = len(raw_inner)
    while i < n:
        ch = raw_inner[i]
        if ch == "\\":
            decoded, i = _decode_escape(raw_inner, i)
            out.extend(decoded)
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    return bytes(out)


def _strip_optional_dict_prefix(stripped: str) -> str | None:
    first_quote = stripped.find('"')
    last_quote = stripped.rfind('"')
    if first_quote == -1 or last_quote <= first_quote or last_quote != len(stripped) - 1:
        return None
    if first_quote == 0:
        return stripped[1:-1]
    prefix = stripped[:first_quote]
    if not prefix.endswith("=") or len(prefix) < 2:
        return None
    key = prefix[:-1]
    if any(ch.isspace() or ch in {'"', "\\"} for ch in key):
        return None
    return stripped[first_quote + 1 : last_quote]


def _decode_dict_escape(inner: str, index: int) -> tuple[bytes, int] | None:
    n = len(inner)
    if index + 1 >= n:
        return None
    nxt = inner[index + 1]
    if escaped := _SIMPLE_ESCAPES.get(nxt):
        return escaped, index + 2
    if nxt == "x" and index + 3 < n:
        hex_part = inner[index + 2 : index + 4]
        if all(c in string.hexdigits for c in hex_part):
            return bytes((int(hex_part, 16),)), index + 4
    return None


def parse_dict_line(line: str) -> bytes | None:
    """Parse an existing libFuzzer `.dict` line into raw bytes using strict ParseOneDictionaryEntry grammar.

    Args:
        line (str): Single line from an existing `.dict` file.

    Returns:
        bytes | None: Decoded entry bytes, or None for blank/comment/invalid lines.
    """
    stripped = line.strip()
    if not stripped or stripped.startswith("#"):
        return None
    inner = _strip_optional_dict_prefix(stripped)
    if inner is None:
        return None

    out = bytearray()
    i = 0
    while i < len(inner):
        ch = inner[i]
        if ch == '"':
            return None
        if ch == "\\":
            decoded = _decode_dict_escape(inner, i)
            if decoded is None:
                return None
            chunk, i = decoded
            out.extend(chunk)
        else:
            out.extend(ch.encode("utf-8"))
            i += 1
    return bytes(out) if out else None


def parse_recommended_token(raw_inner: str) -> bytes:
    """Decode a libFuzzer Recommended dictionary inner string supporting octal escapes.

    Args:
        raw_inner (str): Inner quoted token from libFuzzer stdout/stderr logs.

    Returns:
        bytes: Raw byte token corresponding to the Recommended dictionary entry.
    """
    return _decode_token(raw_inner)


def extract_recommended_from_text(log_text: str) -> dict[bytes, int]:
    """Extract Recommended dictionary entries and aggregate `Uses` counts from logs.

    Args:
        log_text (str): Full text content of a fuzzer log file.

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


def _has_mixed_alnum_run(text: str) -> bool:
    return any(any(c.isalpha() for c in run) and any(c.isdigit() for c in run) for run in _ALNUM_RUN_RE.findall(text))


def _needs_hex_shield(raw: bytes, hex_words: frozenset[str] = frozenset()) -> bool:
    r"""Detect substrings that should be hex-encoded to avoid secret/typo false positives.

    Args:
        raw (bytes): Candidate dictionary entry bytes.
        hex_words (frozenset[str]): Lowercase substrings to always hex-encode.

    Returns:
        bool: True when encoding every byte as `\xhh` avoids false positives while preserving bytes.
    """
    if raw.lower() in _TYPO_EXACT_HEX_TOKENS:
        return True
    text = raw.decode("latin-1")
    lower = text.lower()
    if ("://" in text and "@" in text) or any(word in lower for word in hex_words):
        return True
    if any(prefix in lower for prefix in _SECRET_PREFIXES):
        return True
    return _has_mixed_alnum_run(text)


def format_dict_entry(raw: bytes, *, force_hex: bool = False, hex_words: frozenset[str] = frozenset()) -> str:
    r"""Serialize a raw byte sequence into a libFuzzer `.dict` quoted string.

    Args:
        raw (bytes): Raw dictionary entry bytes.
        force_hex (bool): Force full `\xhh` hex escaping for every byte.
        hex_words (frozenset[str]): Substrings that trigger full hex escaping.

    Returns:
        str: Quoted pure-ASCII dictionary entry using `\xhh` escapes for non-printable bytes.
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


def _resolve_routes_file(repo_root: Path) -> Path:
    routes_file = repo_root / "mailjet_rest" / "routes.py"
    if routes_file.is_file():
        return routes_file
    spec = importlib.util.find_spec("mailjet_rest.routes")
    return Path(spec.origin).resolve() if spec and spec.origin else routes_file


def harvest_sdk_route_tokens(repo_root: Path) -> set[bytes]:
    """Extract static route names, path segments, and Wave 6 protocol tokens from AST.

    Args:
        repo_root (Path): Repository root directory containing `mailjet_rest/routes.py`.

    Returns:
        set[bytes]: Validated 1..128 byte SDK protocol and routing tokens.
    """
    routes_file = _resolve_routes_file(repo_root)
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


def _find_target_log(target_dir: Path, fuzzer_name: str) -> Path | None:
    if target_dir.is_symlink():
        return None
    for candidate in (
        target_dir / "fuzz_output.log",
        target_dir / "fuzzer_output.log",
        target_dir / f"{fuzzer_name}.log",
    ):
        if not candidate.is_symlink() and candidate.is_file():
            return candidate
    return None


def discover_fuzzer_logs(
    fuzz_dir: Path = DEFAULT_FUZZ_DIR,
    logs_dir: Path = DEFAULT_LOGS_DIR,
) -> list[Path]:
    """Map `tests/fuzz/<fuzzer_file_name>.py` targets to `logs/<fuzzer_file_name>/fuzz_output.log`.

    Args:
        fuzz_dir (Path): Directory containing fuzz target scripts (`*.py`).
        logs_dir (Path): Root directory containing per-fuzzer log subdirectories.

    Returns:
        list[Path]: Sorted list of existing log file paths matching discovered fuzz targets.
    """
    if not fuzz_dir.is_dir() or not logs_dir.is_dir():
        return []

    discovered: list[Path] = []
    for fuzz_script in sorted(fuzz_dir.glob("*.py")):
        if fuzz_script.is_symlink() or fuzz_script.name.startswith("_"):
            continue
        fuzzer_name = fuzz_script.stem
        if found := _find_target_log(logs_dir / fuzzer_name, fuzzer_name):
            discovered.append(found)
    return discovered


def _read_zip_member_bounded(archive: zipfile.ZipFile, info: zipfile.ZipInfo, remaining: int) -> bytes:
    if info.file_size > remaining:
        msg = f"Zip archive exceeds maximum uncompressed size ({MAX_UNCOMPRESSED_BYTES} bytes)."
        raise ValueError(msg)
    chunks: list[bytes] = []
    read_total = 0
    with archive.open(info, "r") as member:
        while chunk := member.read(_DOWNLOAD_CHUNK_SIZE):
            read_total += len(chunk)
            if read_total > remaining:
                msg = f"Zip archive exceeds maximum uncompressed size ({MAX_UNCOMPRESSED_BYTES} bytes)."
                raise ValueError(msg)
            chunks.append(chunk)
    return b"".join(chunks)


def _collect_from_zip(zip_bytes: bytes) -> Counter[bytes]:
    totals: Counter[bytes] = Counter()
    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        infos = archive.infolist()
        if len(infos) > MAX_ZIP_MEMBERS:
            msg = f"Zip archive exceeds maximum member count ({MAX_ZIP_MEMBERS})."
            raise ValueError(msg)
        total_uncompressed = 0
        for info in infos:
            if info.is_dir():
                continue
            member_bytes = _read_zip_member_bounded(archive, info, MAX_UNCOMPRESSED_BYTES - total_uncompressed)
            total_uncompressed += len(member_bytes)
            totals.update(extract_recommended_from_text(member_bytes.decode("utf-8", errors="replace")))
    return totals


def collect_from_path(target: Path) -> Counter[bytes]:
    """Recursively harvest Recommended dictionary entries from a log file, zip, or directory.

    Args:
        target (Path): File, archive, or directory path to scan.

    Returns:
        Counter[bytes]: Aggregated counts of discovered dictionary entries.
    """
    totals: Counter[bytes] = Counter()
    if target.is_symlink():
        return totals
    if target.is_dir():
        for child in sorted(target.rglob("*")):
            is_log_or_zip = child.suffix.lower() in {".txt", ".log", ".zip"} or child.name == "fuzzer_output.log"
            if not child.is_symlink() and child.is_file() and is_log_or_zip:
                totals.update(collect_from_path(child))
        return totals

    if target.suffix.lower() == ".zip":
        totals.update(_collect_from_zip(target.read_bytes()))
        return totals

    text = target.read_text(encoding="utf-8", errors="replace")
    totals.update(extract_recommended_from_text(text))
    return totals


def _is_allowed_github_host(host: str) -> bool:
    return (
        host == "api.github.com"
        or (host.endswith(".blob.core.windows.net") and host != ".blob.core.windows.net")
        or (host.endswith(".actions.githubusercontent.com") and host != ".actions.githubusercontent.com")
    )


def _build_validated_github_url(url: str) -> tuple[str, str]:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    has_userinfo = bool(parsed.username or parsed.password)
    if parsed.scheme != "https" or not _is_allowed_github_host(host) or has_userinfo or parsed.port not in {None, 443}:
        msg = f"Disallowed GitHub log URL: {url!r}"
        raise ValueError(msg)
    safe_url = urlunparse(("https", host, parsed.path or "/", "", parsed.query, ""))
    return host, safe_url


def _check_content_length_cap(resp_headers: dict[str, str], max_bytes: int) -> None:
    raw_len = resp_headers.get("content-length")
    if raw_len is None:
        return
    try:
        parsed_len = int(raw_len)
    except ValueError:
        return
    if parsed_len > max_bytes:
        msg = f"HTTP response Content-Length ({raw_len}) exceeds maximum download limit ({max_bytes} bytes)."
        raise ValueError(msg)


def _read_bounded_response_bytes(resp: Any, resp_headers: dict[str, str], max_bytes: int) -> bytes:
    _check_content_length_cap(resp_headers, max_bytes)
    iter_content: Any = getattr(resp, "iter_content", None)
    if not callable(iter_content):
        content = bytes(resp.content)
        if len(content) > max_bytes:
            msg = f"HTTP response exceeds maximum download limit ({max_bytes} bytes)."
            raise ValueError(msg)
        return content

    chunks: list[bytes] = []
    total = 0
    chunk_stream = cast("Callable[..., Iterable[bytes]]", iter_content)(chunk_size=_DOWNLOAD_CHUNK_SIZE)
    for chunk in chunk_stream:
        if not chunk:
            continue
        total += len(chunk)
        if total > max_bytes:
            msg = f"HTTP response exceeds maximum download limit ({max_bytes} bytes)."
            raise ValueError(msg)
        chunks.append(chunk)
    return b"".join(chunks)


def _issue_github_get(safe_url: str, headers: dict[str, str]) -> Any:
    try:
        return requests.get(
            safe_url,
            headers=headers,
            timeout=30.0,
            verify=True,
            allow_redirects=False,
            stream=True,
        )
    except TypeError as exc:
        if "stream" not in str(exc):
            raise
        return requests.get(safe_url, headers=headers, timeout=30.0, verify=True, allow_redirects=False)


def _github_https_get(
    url: str,
    token: str | None,
    *,
    max_bytes: int | None = None,
) -> tuple[int, bytes, dict[str, str]]:
    limit = MAX_DOWNLOAD_BYTES if max_bytes is None else max_bytes
    current_url = url
    current_token = token
    for _ in range(4):
        host, safe_url = _build_validated_github_url(current_url)
        headers: dict[str, str] = {"User-Agent": "mailjet-fuzzer-dict-harvester/1.0"}
        if host == "api.github.com":
            headers["Accept"] = "application/vnd.github+json"
            if current_token:
                headers["Authorization"] = f"Bearer {current_token}"

        resp = _issue_github_get(safe_url, headers)
        try:
            resp_headers = {k.lower(): v for k, v in resp.headers.items()}
            if resp.status_code in {301, 302, 303, 307, 308} and (loc := resp_headers.get("location")):
                current_url = loc
                current_token = None
                continue
            body = _read_bounded_response_bytes(resp, resp_headers, limit)
            return resp.status_code, body, resp_headers
        finally:
            close_fn = getattr(resp, "close", None)
            if callable(close_fn):
                close_fn()

    msg = "Exceeded maximum redirect hops while fetching GitHub Actions logs."
    raise ValueError(msg)


def _validate_github_query(repo: str, workflows: list[str]) -> None:
    if not _REPO_SLUG_RE.match(repo):
        msg = f"Invalid repository slug: {repo!r}"
        raise ValueError(msg)
    for workflow in workflows:
        if not _WORKFLOW_FILE_RE.match(workflow):
            msg = f"Invalid workflow filename: {workflow!r}"
            raise ValueError(msg)


def load_harvest_state(state_path: Path) -> tuple[set[int], set[int]]:
    """Load previously processed GitHub Actions run and job IDs from JSON state.

    Returns:
        tuple[set[int], set[int]]: ``(processed_run_ids, processed_job_ids)``.
    """
    if not state_path.is_file():
        return set(), set()
    raw: dict[str, Any] = json.loads(state_path.read_text(encoding="utf-8"))
    run_ids = {int(x) for x in raw.get("processed_run_ids", []) if isinstance(x, int)}
    job_ids = {int(x) for x in raw.get("processed_job_ids", []) if isinstance(x, int)}
    return run_ids, job_ids


def save_harvest_state(state_path: Path, run_ids: set[int], job_ids: set[int]) -> None:
    """Persist processed GitHub Actions run and job IDs to JSON state."""
    payload = {
        "processed_run_ids": sorted(run_ids),
        "processed_job_ids": sorted(job_ids),
    }
    state_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")


def _discover_completed_runs(repo: str, workflows: list[str], cutoff: str, token: str | None) -> set[int]:
    discovered: set[int] = set()
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
                discovered.add(run["id"])
    return discovered


def _fetch_unprocessed_logs(
    repo: str,
    resource_kind: str,
    item_ids: Iterable[int],
    processed_ids: set[int] | None,
    token: str | None,
    parser: Callable[[bytes], Counter[bytes] | dict[bytes, int]],
) -> Counter[bytes]:
    totals: Counter[bytes] = Counter()
    skip = processed_ids if processed_ids is not None else set()
    for item_id in item_ids:
        if item_id in skip:
            continue
        url = f"https://api.github.com/repos/{repo}/actions/{resource_kind}/{item_id}/logs"
        status, body, _ = _github_https_get(url, token)
        if status == 200 and body:
            totals.update(parser(body))
        if status in {200, 410} and processed_ids is not None:
            processed_ids.add(item_id)
    return totals


def _fetch_unprocessed_runs(
    repo: str,
    run_ids: set[int],
    processed_run_ids: set[int] | None,
    token: str | None,
) -> Counter[bytes]:
    return _fetch_unprocessed_logs(repo, "runs", sorted(run_ids), processed_run_ids, token, _collect_from_zip)


def _fetch_unprocessed_jobs(
    repo: str,
    job_ids: list[int],
    processed_job_ids: set[int] | None,
    token: str | None,
) -> Counter[bytes]:
    return _fetch_unprocessed_logs(
        repo,
        "jobs",
        job_ids,
        processed_job_ids,
        token,
        lambda body: extract_recommended_from_text(body.decode("utf-8", errors="replace")),
    )


def collect_from_github(
    repo: str,
    workflows: list[str],
    days: int,
    job_ids: list[int],
    run_ids: list[int],
    *,
    processed_run_ids: set[int] | None = None,
    processed_job_ids: set[int] | None = None,
) -> Counter[bytes]:
    """Fetch logs for unprocessed GitHub Actions runs/jobs and harvest Recommended dictionary entries.

    Args:
        repo (str): GitHub repository slug (`owner/name`).
        workflows (list[str]): Workflow filenames to query.
        days (int): Lookback window in days for completed workflow runs.
        job_ids (list[int]): Explicit GitHub Actions job IDs to inspect.
        run_ids (list[int]): Explicit GitHub Actions run IDs to inspect.
        processed_run_ids (set[int] | None): Optional set of already-processed run IDs (updated in place).
        processed_job_ids (set[int] | None): Optional set of already-processed job IDs (updated in place).

    Returns:
        Counter[bytes]: Aggregated Recommended dictionary entries fetched from GitHub Actions.
    """
    from datetime import datetime, timedelta, timezone  # ruff: ignore[import-outside-top-level]

    _validate_github_query(repo, workflows)
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).strftime("%Y-%m-%d")
    seen_runs = set(run_ids) | _discover_completed_runs(repo, workflows, cutoff, token)

    totals = _fetch_unprocessed_runs(repo, seen_runs, processed_run_ids, token)
    totals.update(_fetch_unprocessed_jobs(repo, job_ids, processed_job_ids, token))
    return totals


def _canonicalize_existing_lines(
    existing_lines: list[str],
    *,
    hex_words: frozenset[str],
) -> tuple[set[bytes], list[str]]:
    existing_bytes: set[bytes] = set()
    canonical_existing: list[str] = []
    for line in existing_lines:
        parsed = parse_dict_line(line)
        if parsed is None or not (1 <= len(parsed) <= MAX_DICT_ENTRY_BYTES) or parsed in existing_bytes:
            continue
        existing_bytes.add(parsed)
        canonical_existing.append(format_dict_entry(parsed, hex_words=hex_words))
    return existing_bytes, canonical_existing


def merge_dictionary(
    dict_path: Path,
    candidate_counts: Counter[bytes],
    *,
    min_uses: int = 1,
    hex_words: frozenset[str] = frozenset(),
    write: bool = False,
) -> tuple[int, int, list[str]]:
    """Non-destructively merge newly harvested byte tokens into `fuzzer.dict`.

    Args:
        dict_path (Path): Target `.dict` file path.
        candidate_counts (Counter[bytes]): Candidate tokens mapped to aggregate use counts.
        min_uses (int): Minimum aggregate `Uses` threshold required to include a token.
        hex_words (frozenset[str]): Lowercase substrings to force-encode as hex.
        write (bool): Whether to write the updated dictionary back to `dict_path`.

    Returns:
        tuple[int, int, list[str]]: `(existing_line_count, added_count, sorted_merged_lines)`.
    """
    existing_lines = dict_path.read_text(encoding="utf-8").splitlines() if dict_path.exists() else []
    existing_bytes, canonical_existing = _canonicalize_existing_lines(existing_lines, hex_words=hex_words)

    new_lines: list[str] = []
    for raw_token, uses in candidate_counts.items():
        if uses < min_uses or not (1 <= len(raw_token) <= MAX_DICT_ENTRY_BYTES) or raw_token in existing_bytes:
            continue
        existing_bytes.add(raw_token)
        new_lines.append(format_dict_entry(raw_token, hex_words=hex_words))

    merged_lines = sorted(set(canonical_existing) | set(new_lines))
    if write and (new_lines or merged_lines != existing_lines):
        dict_path.write_text("\n".join(merged_lines) + "\n", encoding="utf-8")

    return len(existing_lines), len(new_lines), merged_lines


def _collect_github_candidates(args: argparse.Namespace) -> Counter[bytes]:
    processed_runs, processed_jobs = (set(), set()) if args.force_refetch else load_harvest_state(args.state_path)
    totals = collect_from_github(
        args.repo,
        args.workflows,
        args.days,
        args.job_id,
        args.run_id,
        processed_run_ids=processed_runs,
        processed_job_ids=processed_jobs,
    )
    if args.write:
        save_harvest_state(args.state_path, processed_runs, processed_jobs)
    return totals


def _collect_candidates(args: argparse.Namespace) -> Counter[bytes]:
    totals: Counter[bytes] = Counter()
    log_paths: list[Path] = list(args.log_path)

    if args.local or (not log_paths and not args.repo):
        log_paths.extend(discover_fuzzer_logs(fuzz_dir=args.fuzz_dir, logs_dir=args.logs_dir))

    for path_item in log_paths:
        totals.update(collect_from_path(path_item))

    if args.repo:
        totals.update(_collect_github_candidates(args))

    if args.sync_routes:
        for tok in harvest_sdk_route_tokens(REPO_ROOT):
            totals[tok] = max(totals[tok], args.min_uses)

    return totals


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for harvesting ClusterFuzzLite and local libFuzzer dictionary suggestions.

    Args:
        argv (list[str] | None): Optional CLI argument vector.

    Returns:
        int: Process exit code (`0` when cleanly synced or updated, `1` on `--check` drift).
    """
    parser = argparse.ArgumentParser(description="Harvest libFuzzer Recommended dictionary entries into fuzzer.dict.")
    parser.add_argument(
        "--local",
        action="store_true",
        help="Auto-discover logs/<fuzzer>/fuzz_output.log from tests/fuzz/<fuzzer>.py (default when no source is given).",
    )
    parser.add_argument(
        "--fuzz-dir", type=Path, default=DEFAULT_FUZZ_DIR, help="Directory with fuzz target *.py files."
    )
    parser.add_argument(
        "--logs-dir", type=Path, default=DEFAULT_LOGS_DIR, help="Root directory with local fuzzer logs."
    )
    parser.add_argument(
        "--log-path", type=Path, action="append", default=[], help="Explicit log file, zip archive, or directory."
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
    parser.add_argument("--state-path", type=Path, default=DEFAULT_STATE_PATH, help="Processed CI run/job state JSON.")
    parser.add_argument("--force-refetch", action="store_true", help="Ignore processed CI state and refetch all logs.")
    parser.add_argument("--min-uses", type=int, default=1, help="Minimum aggregate Uses threshold.")
    parser.add_argument("--sync-routes", action="store_true", help="Include static ROUTE_MAP and protocol tokens.")
    parser.add_argument("--hex-word", action="append", default=[], help="Substring to force-hex for typos hygiene.")
    mode = parser.add_mutually_exclusive_group()
    mode.add_argument("--write", action="store_true", help="Write merged entries to --dict-path.")
    mode.add_argument("--check", action="store_true", help="Fail with exit code 1 if new entries would be added.")
    mode.add_argument("--dry-run", action="store_true", help="Preview summary without modifying --dict-path.")

    args = parser.parse_args(argv)
    totals = _collect_candidates(args)

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
