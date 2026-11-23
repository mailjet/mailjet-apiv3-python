"""Offline architectural gate enforcing scope layout and 1:1 Sync Client vs AsyncClient parity."""

from __future__ import annotations

import ast
from pathlib import Path

from mailjet_rest.routes import ROUTE_MAP
from tests.integration.live_matrix._matrix_spec import COVERED_LIVE_ROUTES


INTEGRATION_ROOT: Path = Path(__file__).resolve().parent
SCOPE_DIRS: tuple[str, ...] = ("contracts", "local_loopback", "live_workflows", "live_matrix")

STRICT_PARITY_PAIRS: tuple[tuple[str, int], ...] = (
    ("contracts/test_routes_contract", 3),
    ("live_workflows/test_workflows", 31),
    ("live_matrix/test_endpoints_matrix", 12),
)


def _extract_test_functions(py_file: Path) -> list[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    return [
        node.name
        for node in tree.body
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name.startswith("test_")
    ]


def _imported_mailjet_client_names(py_file: Path) -> set[str]:
    tree = ast.parse(py_file.read_text(encoding="utf-8"), filename=str(py_file))
    names: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and node.module and node.module.startswith("mailjet_rest"):
            names.update(alias.name for alias in node.names)
    return names


def test_scope_directories_and_sync_async_file_pairing() -> None:
    """Every scope directory exists and pairs every *_sync.py suite with a matching *_async.py suite."""
    assert (INTEGRATION_ROOT / "test_local_https_integration.py").is_file()
    assert (INTEGRATION_ROOT / "fixtures" / "openapi_operations_manifest.json").is_file()

    sync_files: list[Path] = []
    for scope in SCOPE_DIRS:
        scope_dir = INTEGRATION_ROOT / scope
        assert scope_dir.is_dir(), f"Missing scope directory: {scope_dir}"
        syncs = sorted(scope_dir.glob("*_sync.py"))
        asyncs = sorted(scope_dir.glob("*_async.py"))
        assert syncs, f"Scope {scope} has no *_sync.py modules"
        assert [p.name.removesuffix("_sync.py") for p in syncs] == [p.name.removesuffix("_async.py") for p in asyncs], (
            f"Sync/Async file mismatch in {scope}: sync={syncs}, async={asyncs}"
        )
        sync_files.extend(syncs)

        for async_file in asyncs:
            source = async_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(async_file))
            has_async = any(isinstance(n, (ast.AsyncFunctionDef, ast.AsyncWith, ast.Await)) for n in ast.walk(tree))
            assert has_async, f"{async_file.name} does not contain async/await execution"
            imported = _imported_mailjet_client_names(async_file)
            assert "Client" not in imported, f"{async_file.name} must not import synchronous Client"

        for sync_file in syncs:
            imported = _imported_mailjet_client_names(sync_file)
            assert "AsyncClient" not in imported, f"{sync_file.name} must not import AsyncClient"

    assert len(sync_files) == 6


def test_strict_one_to_one_sync_async_test_function_parity() -> None:
    """Assert 1:1 test_* function parity across contracts, live_workflows, and live_matrix pairs."""
    for stem, expected_count in STRICT_PARITY_PAIRS:
        sync_file = INTEGRATION_ROOT / f"{stem}_sync.py"
        async_file = INTEGRATION_ROOT / f"{stem}_async.py"
        sync_funcs = _extract_test_functions(sync_file)
        async_funcs = _extract_test_functions(async_file)
        assert len(sync_funcs) == expected_count, f"{sync_file.name}: expected {expected_count}, got {len(sync_funcs)}"
        assert set(sync_funcs) == set(async_funcs), (
            f"1:1 Sync/Async test function drift in {stem}: "
            f"sync-only={sorted(set(sync_funcs) - set(async_funcs))}, "
            f"async-only={sorted(set(async_funcs) - set(sync_funcs))}"
        )


def test_live_89_route_registry_parity() -> None:
    """Confirm live matrix specification covers every route in ROUTE_MAP (89/89)."""
    assert set(COVERED_LIVE_ROUTES) == set(ROUTE_MAP)
    assert len(COVERED_LIVE_ROUTES) == 89
