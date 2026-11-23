#!/usr/bin/env python3
"""Atheris fuzzing target for attachment path traversal, file size limits, and multipart upload validation."""

from __future__ import annotations

import atexit
import io
import logging
import os
import shutil
import tempfile
import sys
import warnings
from pathlib import Path
from typing import Any

import atheris


warnings.simplefilter("ignore")
logging.disable(logging.CRITICAL)

with atheris.instrument_imports(include=["mailjet_rest"]):
    from mailjet_rest.utils.filesystem_security import (
        check_file_size,
        validate_attachment_path,
        validate_multipart_files,
    )
    from mailjet_rest.utils.guardrails import SecurityGuard


_SAFE_ROOT = Path(tempfile.mkdtemp(prefix="mj_fuzz_fs_"))
_OUTSIDE_ROOT = Path(tempfile.mkdtemp(prefix="mj_fuzz_fs_out_"))
atexit.register(shutil.rmtree, _SAFE_ROOT, True)
atexit.register(shutil.rmtree, _OUTSIDE_ROOT, True)

_VALID_FILE = _SAFE_ROOT / "allowed_attachment.txt"
_VALID_FILE.write_bytes(b"mailjet-fuzz-attachment-bytes")
_SUBDIR = _SAFE_ROOT / "nested_dir"
_SUBDIR.mkdir(exist_ok=True)
_OUTSIDE_FILE = _OUTSIDE_ROOT / "outside.txt"
_OUTSIDE_FILE.write_bytes(b"outside-boundary")
_SYMLINK_FILE = _SAFE_ROOT / "symlink_attachment.txt"
try:
    if not _SYMLINK_FILE.exists():
        _SYMLINK_FILE.symlink_to(_VALID_FILE)
except OSError:
    # Some minimal containers restrict symlink creation; handled gracefully.
    pass


def _fuzz_multipart_files(fdp: atheris.FuzzedDataProvider) -> None:
    inject_bad = fdp.ConsumeBool()
    bad_char = fdp.PickValueInList(["\r", "\n", "\x00"])
    safe_base = fdp.ConsumeUnicodeNoSurrogates(16).replace("\r", "").replace("\n", "").replace("\x00", "") or "file"

    field_name: Any = f"{safe_base}{bad_char}hdr" if (inject_bad and fdp.ConsumeBool()) else safe_base
    if fdp.ConsumeBool():
        filename: Any = (f"{safe_base}{bad_char}.txt" if inject_bad else f"{safe_base}.txt").encode("utf-8")
    else:
        filename = f"{safe_base}{bad_char}.txt" if inject_bad else f"{safe_base}.txt"

    content_type: Any = (
        bytearray(b"text/plain\r\nX-Injected: 1")
        if (inject_bad and fdp.ConsumeBool())
        else fdp.PickValueInList(["text/plain", "application/pdf", None])
    )
    custom_headers: Any = (
        {"X-Fuzz": f"val{bad_char}smuggle"} if (inject_bad and fdp.ConsumeBool()) else {"X-Fuzz": "clean"}
    )

    spec_len = fdp.ConsumeIntInRange(1, 4)
    raw_spec = (filename, io.BytesIO(b"payload"), content_type, custom_headers)[:spec_len]
    files: Any = {field_name: raw_spec} if fdp.ConsumeBool() else [(field_name, raw_spec)]

    contains_injection = (
        (isinstance(field_name, (str, bytes, bytearray)) and any(c in str(field_name) for c in ("\r", "\n", "\x00")))
        or (
            isinstance(filename, (str, bytes, bytearray))
            and any(
                c in (filename if isinstance(filename, str) else filename.decode("latin-1"))
                for c in ("\r", "\n", "\x00")
            )
        )
        or (
            isinstance(content_type, (str, bytes, bytearray))
            and any(
                c in (content_type if isinstance(content_type, str) else bytes(content_type).decode("latin-1"))
                for c in ("\r", "\n", "\x00")
            )
        )
        or (
            isinstance(custom_headers, dict)
            and any(c in str(v) for v in custom_headers.values() for c in ("\r", "\n", "\x00"))
        )
    )

    try:
        validate_multipart_files(files, header_sanitizer=SecurityGuard.sanitize_headers)
    except ValueError:
        return

    if contains_injection:
        msg = "validate_multipart_files failed to block CRLF/NUL smuggling vector"
        raise AssertionError(msg)


def _fuzz_attachment_path(fdp: atheris.FuzzedDataProvider) -> None:
    scenario = fdp.ConsumeIntInRange(0, 6)
    safe_base: Path | None = _SAFE_ROOT if fdp.ConsumeBool() else None

    if scenario == 0:
        resolved = validate_attachment_path(_VALID_FILE, safe_base_dir=_SAFE_ROOT)
        if resolved != _VALID_FILE.resolve():
            msg = f"Expected {_VALID_FILE.resolve()}, got {resolved}"
            raise AssertionError(msg)
        return

    if scenario == 1:
        bad_target = f"attachment\x00_{fdp.ConsumeUnicodeNoSurrogates(12)}.pdf"
        candidate: Any = bad_target.encode("utf-8") if fdp.ConsumeBool() else bad_target
        try:
            validate_attachment_path(candidate, safe_base_dir=safe_base)
        except ValueError:
            return
        msg = "validate_attachment_path failed to reject NUL byte path (CWE-22)"
        raise AssertionError(msg)

    if scenario == 2 and _SYMLINK_FILE.is_symlink():
        try:
            validate_attachment_path(_SYMLINK_FILE, safe_base_dir=safe_base)
        except ValueError:
            return
        msg = "validate_attachment_path failed to reject symlink attachment (CWE-22)"
        raise AssertionError(msg)

    if scenario == 3:
        try:
            validate_attachment_path(_OUTSIDE_FILE, safe_base_dir=_SAFE_ROOT)
        except ValueError:
            return
        msg = "validate_attachment_path allowed attachment outside safe_base_dir"
        raise AssertionError(msg)

    if scenario == 4:
        try:
            validate_attachment_path("../etc/passwd", safe_base_dir=None)
        except ValueError:
            return
        msg = "validate_attachment_path allowed '..' traversal path"
        raise AssertionError(msg)

    raw_path = os.fspath(str(_SUBDIR)) if scenario == 5 else fdp.ConsumeUnicodeNoSurrogates(48)
    try:
        validate_attachment_path(raw_path, safe_base_dir=safe_base)
    except (ValueError, FileNotFoundError, TypeError):
        # Expected rejection for missing files, directories, or unsafe paths.
        return


def _fuzz_file_size_check(fdp: atheris.FuzzedDataProvider) -> None:
    file_size = _VALID_FILE.stat().st_size
    if fdp.ConsumeBool():
        cap = fdp.ConsumeIntInRange(-1, file_size * 2)
        try:
            check_file_size(_VALID_FILE, max_size_bytes=cap)
        except ValueError:
            if cap >= file_size:
                msg = f"check_file_size falsely rejected file of size {file_size} under cap {cap}"
                raise AssertionError(msg) from None
            return
        if file_size > cap:
            msg = f"check_file_size allowed file {file_size} > max_size_bytes {cap}"
            raise AssertionError(msg)
        return

    try:
        check_file_size(_SUBDIR, max_size_bytes=1024)
    except ValueError:
        return
    msg = "check_file_size must reject directories"
    raise AssertionError(msg)


def TestOneInput(data: bytes) -> None:
    """Execute one Atheris iteration across multipart metadata and filesystem security helpers."""
    if len(data) < 6:
        return

    fdp = atheris.FuzzedDataProvider(data)
    mode = fdp.ConsumeIntInRange(0, 2)
    try:
        if mode == 0:
            _fuzz_multipart_files(fdp)
        elif mode == 1:
            _fuzz_attachment_path(fdp)
        else:
            _fuzz_file_size_check(fdp)
    except (ValueError, FileNotFoundError, TypeError):
        # Expected filesystem and multipart rejections under adversarial inputs.
        return
    except Exception as exc:
        msg = f"UNHANDLED CRASH in fuzz_multipart_and_filesystem: {type(exc).__name__} - {exc}"
        raise RuntimeError(msg) from exc


def main() -> None:
    """Run Atheris fuzzing loop for multipart and filesystem security helpers."""
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()


if __name__ == "__main__":
    main()
