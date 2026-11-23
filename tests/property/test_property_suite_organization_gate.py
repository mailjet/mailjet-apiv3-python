"""Offline architectural gate enforcing tests/property scope layout and sync/async isolation."""

from __future__ import annotations

import ast
from pathlib import Path


PROPERTY_ROOT: Path = Path(__file__).resolve().parent
SCOPE_DIRS: tuple[str, ...] = ("clients", "endpoints", "builders", "security")
STRICT_SYNC_ASYNC_MODULE_PAIRS: tuple[str, ...] = (
    "clients/test_client_properties",
    "clients/test_client_state",
    "endpoints/test_pagination_properties",
)


def _imported_mailjet_symbols(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("mailjet_rest"):
            symbols.update(alias.name for alias in node.names)
    return symbols


def test_property_root_has_only_gate_and_four_scope_subpackages() -> None:
    """Ensure tests/property root has no flat catch-all files and organizes tests across 4 scopes."""
    root_files = {p.name for p in PROPERTY_ROOT.iterdir() if p.is_file()}
    assert root_files == {"__init__.py", "test_property_suite_organization_gate.py"}

    root_dirs = {
        p.name for p in PROPERTY_ROOT.iterdir() if p.is_dir() and p.name != "__pycache__" and not p.name.startswith(".")
    }
    assert root_dirs == set(SCOPE_DIRS)

    for scope in SCOPE_DIRS:
        scope_dir = PROPERTY_ROOT / scope
        assert (scope_dir / "__init__.py").is_file(), f"Missing __init__.py in {scope_dir}"
        test_modules = sorted(scope_dir.glob("test_*.py"))
        assert len(test_modules) >= 2 or scope == "security", f"Unexpected test module layout in {scope_dir}"
        assert test_modules, f"Scope {scope} must contain test_*.py modules"


def test_property_sync_async_separation_and_pair_symmetry() -> None:
    """Enforce strict sync (*_sync.py) vs async (*_async.py) isolation across property scopes."""
    discovered_stems: set[str] = set()

    for scope in SCOPE_DIRS:
        scope_dir = PROPERTY_ROOT / scope
        syncs = sorted(scope_dir.glob("*_sync.py"))
        asyncs = sorted(scope_dir.glob("*_async.py"))
        sync_stems = [f"{scope}/{p.name.removesuffix('_sync.py')}" for p in syncs]
        async_stems = [f"{scope}/{p.name.removesuffix('_async.py')}" for p in asyncs]
        assert sync_stems == async_stems, f"Mismatched sync/async pairs in {scope}: {sync_stems} vs {async_stems}"
        discovered_stems.update(sync_stems)

    assert discovered_stems == set(STRICT_SYNC_ASYNC_MODULE_PAIRS)

    for stem in STRICT_SYNC_ASYNC_MODULE_PAIRS:
        sync_file = PROPERTY_ROOT / f"{stem}_sync.py"
        async_file = PROPERTY_ROOT / f"{stem}_async.py"
        assert sync_file.is_file() and async_file.is_file()

        sync_imports = _imported_mailjet_symbols(sync_file)
        assert not ({"AsyncClient", "AsyncEndpoint"} & sync_imports), (
            f"{sync_file.name} must not import AsyncClient/AsyncEndpoint: {sync_imports}"
        )

        async_source = async_file.read_text(encoding="utf-8")
        async_imports = _imported_mailjet_symbols(async_file)
        assert not ({"Client", "Endpoint"} & async_imports), (
            f"{async_file.name} must not import synchronous Client/Endpoint: {async_imports}"
        )

        async_tree = ast.parse(async_source, filename=str(async_file))
        has_async = any(
            isinstance(node, (ast.AsyncFunctionDef, ast.AsyncWith, ast.AsyncFor, ast.Await))
            for node in ast.walk(async_tree)
        )
        assert has_async or "AsyncClientStateMachine" in async_source, (
            f"{async_file.name} must execute async/await or AsyncClientStateMachine paths"
        )
