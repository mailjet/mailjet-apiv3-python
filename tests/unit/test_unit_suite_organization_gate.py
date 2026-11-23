"""Offline architectural gate enforcing tests/unit scope layout, sync/async separation, and mutmut config."""

from __future__ import annotations

import ast
import re
from pathlib import Path


UNIT_ROOT: Path = Path(__file__).resolve().parent
REPO_ROOT: Path = UNIT_ROOT.parents[1]
SCOPE_DIRS: tuple[str, ...] = (
    "clients",
    "endpoints",
    "builders",
    "security",
    "webhooks_and_testing",
    "packaging_and_fuzz",
)
STRICT_SYNC_ASYNC_MODULE_PAIRS: tuple[str, ...] = (
    "clients/test_client",
    "endpoints/test_endpoint",
    "webhooks_and_testing/test_mock_client",
)


def _imported_mailjet_symbols(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    symbols: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("mailjet_rest"):
            symbols.update(alias.name for alias in node.names)
    return symbols


def test_unit_root_has_only_shared_gate_and_six_scope_subpackages() -> None:
    """Ensure tests/unit root has no flat wave/ad-hoc files and organizes all tests across 6 scopes."""
    root_files = {p.name for p in UNIT_ROOT.iterdir() if p.is_file()}
    assert root_files == {"__init__.py", "conftest.py", "test_unit_suite_organization_gate.py"}

    root_dirs = {
        p.name for p in UNIT_ROOT.iterdir() if p.is_dir() and p.name != "__pycache__" and not p.name.startswith(".")
    }
    assert root_dirs == set(SCOPE_DIRS)

    for scope in SCOPE_DIRS:
        scope_dir = UNIT_ROOT / scope
        assert (scope_dir / "__init__.py").is_file(), f"Missing __init__.py in {scope_dir}"
        test_modules = sorted(scope_dir.glob("test_*.py"))
        assert len(test_modules) >= 2, f"Scope {scope} should contain >= 2 focused modules, found {test_modules}"


def test_unit_sync_async_separation_and_pair_symmetry() -> None:
    """Enforce strict sync (*_sync.py) vs async (*_async.py) client/endpoint/mock test isolation."""
    expected_stems = set(STRICT_SYNC_ASYNC_MODULE_PAIRS)
    discovered_stems: set[str] = set()

    for scope in SCOPE_DIRS:
        scope_dir = UNIT_ROOT / scope
        syncs = sorted(scope_dir.glob("*_sync.py"))
        asyncs = sorted(scope_dir.glob("*_async.py"))
        sync_stems = [f"{scope}/{p.name.removesuffix('_sync.py')}" for p in syncs]
        async_stems = [f"{scope}/{p.name.removesuffix('_async.py')}" for p in asyncs]
        assert sync_stems == async_stems, f"Mismatched sync/async pairs in {scope}: {sync_stems} vs {async_stems}"
        discovered_stems.update(sync_stems)

    assert discovered_stems == expected_stems

    for stem in STRICT_SYNC_ASYNC_MODULE_PAIRS:
        sync_file = UNIT_ROOT / f"{stem}_sync.py"
        async_file = UNIT_ROOT / f"{stem}_async.py"
        assert sync_file.is_file() and async_file.is_file()

        sync_imports = _imported_mailjet_symbols(sync_file)
        assert not ({"AsyncClient", "AsyncEndpoint"} & sync_imports), (
            f"{sync_file.name} must not import AsyncClient/AsyncEndpoint: {sync_imports}"
        )

        async_imports = _imported_mailjet_symbols(async_file)
        assert not ({"Client", "Endpoint"} & async_imports), (
            f"{async_file.name} must not import synchronous Client/Endpoint: {async_imports}"
        )

        async_tree = ast.parse(async_file.read_text(encoding="utf-8"), filename=str(async_file))
        has_async = any(
            isinstance(node, (ast.AsyncFunctionDef, ast.AsyncWith, ast.AsyncFor, ast.Await))
            for node in ast.walk(async_tree)
        )
        assert has_async, f"{async_file.name} must execute real async/await code paths"


def test_pyproject_mutmut_ignore_paths_exist() -> None:
    """Confirm every --ignore=tests/... path in [tool.mutmut] exists after reorganization."""
    pyproject_text = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    mutmut_section = re.search(r"\[tool\.mutmut\]\n(.*?)(?=\n\[|\Z)", pyproject_text, flags=re.DOTALL)
    assert mutmut_section is not None
    ignored_paths = re.findall(r"--ignore=(tests/[^\s\"']+)", mutmut_section.group(1))
    assert "tests/unit/packaging_and_fuzz/test_stubs.py" in ignored_paths
    for rel_path in ignored_paths:
        assert (REPO_ROOT / rel_path).is_file(), f"Stale mutmut ignore path in pyproject.toml: {rel_path}"
