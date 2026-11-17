"""Unit tests verifying tracked .pyi stub synchronization and ROUTE_MAP coverage."""

from __future__ import annotations

import ast
from pathlib import Path
import shutil

import scripts.check_stubs as check_stubs
from mailjet_rest.routes import ROUTE_MAP


def test_tracked_stubs_are_synchronized() -> None:
    """Repository .pyi stubs must match AST-generated deterministic output."""
    assert check_stubs.main(["--check"]) == 0


def test_stub_drift_detected_in_temp_copy(tmp_path: Path) -> None:
    """Modifying a tracked .pyi stub causes --check to exit non-zero until --write syncs it."""
    pkg_copy = tmp_path / "mailjet_rest"
    pkg_copy.mkdir()
    for name in ("client.py", "endpoint.py", "routes.py", "client.pyi", "endpoint.pyi"):
        shutil.copy2(Path("mailjet_rest") / name, pkg_copy / name)

    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 0

    (pkg_copy / "client.pyi").write_text("# drifted stub\n", encoding="utf-8")
    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 1

    assert check_stubs.main(["--write", "--package-dir", str(pkg_copy)]) == 0
    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 0


def test_client_stub_exposes_every_route_map_property() -> None:
    """Every static route in ROUTE_MAP is declared on Client in client.pyi."""
    stub_source = Path("mailjet_rest/client.pyi").read_text(encoding="utf-8")
    tree = ast.parse(stub_source)
    client_cls = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == "Client")
    client_props = {
        node.name
        for node in client_cls.body
        if isinstance(node, ast.FunctionDef)
        and any(isinstance(dec, ast.Name) and dec.id == "property" for dec in node.decorator_list)
    }

    expected_routes = {route for route in ROUTE_MAP if route.isidentifier()}
    missing = expected_routes - client_props
    assert not missing, f"Routes missing from client.pyi: {sorted(missing)}"
    assert any(isinstance(node, ast.FunctionDef) and node.name == "__getattr__" for node in client_cls.body)
