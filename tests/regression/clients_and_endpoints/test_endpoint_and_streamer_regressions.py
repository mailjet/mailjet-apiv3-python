"""Endpoint validation and ChunkedStreamer descriptor-closure regression tests."""

from __future__ import annotations

import ast
import asyncio
import os
from pathlib import Path
from typing import Any

import pytest

from mailjet_rest.builders import ChunkedStreamer
from mailjet_rest.client import AsyncClient, Client, _httpx2
from tests.regression.conftest import REPO_ROOT


@pytest.mark.parametrize("bad_id", [None, "", "   ", True])
def test_endpoint_and_async_endpoint_delete_reject_invalid_id(bad_id: Any) -> None:
    """PR #179 #9b: Endpoint.delete and AsyncEndpoint.delete must reject missing, blank, or bool resource IDs."""
    with Client(auth=("pub", "priv")) as sync_client:
        with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
            sync_client.v1_templates.delete(id=bad_id)

    if _httpx2 is not None:

        async def _check() -> None:
            async with AsyncClient(auth=("pub", "priv")) as aclient:
                with pytest.raises(ValueError, match="requires a non-empty, non-boolean resource 'id'"):
                    await aclient.v1_templates.delete(id=bad_id)

        asyncio.run(_check())


def test_chunked_streamer_encode_file_closes_fd_on_fdopen_error_and_lexically_pairs_fd(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """CodeQL #87 (py/file-not-closed): encode_file must close fd if fdopen fails and pair open/close lexically."""
    sample_file = tmp_path / "attachment.txt"
    sample_file.write_bytes(b"hello-mailjet")

    real_open = os.open
    real_close = os.close
    opened_fds: list[int] = []
    closed_fds: list[int] = []

    def _spy_open(path: Any, flags: int, *args: Any, **kwargs: Any) -> int:
        fd = real_open(path, flags, *args, **kwargs)
        opened_fds.append(fd)
        return fd

    def _spy_close(fd: int) -> None:
        closed_fds.append(fd)
        real_close(fd)

    def _fail_fdopen(*_args: Any, **_kwargs: Any) -> Any:
        msg = "simulated fdopen failure"
        raise OSError(msg)

    monkeypatch.setattr(os, "open", _spy_open)
    monkeypatch.setattr(os, "close", _spy_close)
    monkeypatch.setattr(os, "fdopen", _fail_fdopen)

    with pytest.raises(OSError, match="simulated fdopen failure"):
        ChunkedStreamer.encode_file(sample_file, safe_base_dir=tmp_path)

    assert len(opened_fds) == 1
    assert closed_fds == opened_fds, f"Leaked fd(s) {set(opened_fds) - set(closed_fds)} when os.fdopen raised"

    # AST lexical pairing witness so CodeQL py/file-not-closed can prove fd closure within encode_file
    builders_path = REPO_ROOT / "mailjet_rest" / "builders.py"
    tree = ast.parse(builders_path.read_text(encoding="utf-8"), filename=str(builders_path))
    streamer_cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "ChunkedStreamer")
    encode_fn = next(
        node for node in streamer_cls.body if isinstance(node, ast.FunctionDef) and node.name == "encode_file"
    )
    os_calls = {
        node.func.attr
        for node in ast.walk(encode_fn)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "os"
    }
    assert {"open", "fdopen", "close"} <= os_calls
    has_try_finally = any(isinstance(node, ast.Try) and bool(node.finalbody) for node in ast.walk(encode_fn))
    assert has_try_finally, "ChunkedStreamer.encode_file must pair os.open with try/finally os.close"
