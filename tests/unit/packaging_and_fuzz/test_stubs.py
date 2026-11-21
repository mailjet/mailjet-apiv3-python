"""Unit tests verifying tracked .pyi stub synchronization and ROUTE_MAP coverage."""

from __future__ import annotations

import ast
import importlib.util
import shutil
from pathlib import Path

import mailjet_rest
import scripts.check_stubs as check_stubs
from mailjet_rest.routes import ROUTE_MAP


def _package_dir() -> Path:
    assert mailjet_rest.__file__ is not None
    return Path(mailjet_rest.__file__).resolve().parent


def test_tracked_stubs_are_synchronized() -> None:
    """Repository .pyi stubs must match AST-generated deterministic output."""
    assert check_stubs.main(["--check"]) == 0


def test_stub_drift_detected_in_temp_copy(tmp_path: Path) -> None:
    """Modifying a tracked .pyi stub causes --check to exit non-zero until --write syncs it."""
    pkg_copy = tmp_path / "mailjet_rest"
    pkg_copy.mkdir()
    for name in ("client.py", "endpoint.py", "routes.py", "client.pyi", "endpoint.pyi"):
        shutil.copy2(_package_dir() / name, pkg_copy / name)

    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 0

    (pkg_copy / "client.pyi").write_text("# drifted stub\n", encoding="utf-8")
    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 1

    assert check_stubs.main(["--write", "--package-dir", str(pkg_copy)]) == 0
    assert check_stubs.main(["--check", "--package-dir", str(pkg_copy)]) == 0


def _collect_route_properties(tree: ast.Module, class_name: str, expected_return: str) -> set[str]:
    cls_node = next(node for node in tree.body if isinstance(node, ast.ClassDef) and node.name == class_name)
    assert any(isinstance(node, ast.FunctionDef) and node.name == "__getattr__" for node in cls_node.body)
    props: set[str] = set()
    for node in cls_node.body:
        if (
            isinstance(node, ast.FunctionDef)
            and any(isinstance(dec, ast.Name) and dec.id == "property" for dec in node.decorator_list)
            and isinstance(node.returns, ast.Name)
            and node.returns.id == expected_return
        ):
            props.add(node.name)
    return props


def test_client_stub_exposes_every_route_map_property() -> None:
    """Every static route in ROUTE_MAP is declared on Client and AsyncClient in client.pyi."""
    pkg_dir = _package_dir()
    stub_source = (pkg_dir / "client.pyi").read_text(encoding="utf-8")
    tree = ast.parse(stub_source)
    expected_routes = {route for route in ROUTE_MAP if route.isidentifier()}

    for class_name, return_type in (("Client", "Endpoint"), ("AsyncClient", "AsyncEndpoint")):
        client_props = _collect_route_properties(tree, class_name, return_type)
        missing = expected_routes - client_props
        assert not missing, f"Routes missing from {class_name} in client.pyi: {sorted(missing)}"

    ep_stub = (pkg_dir / "endpoint.pyi").read_text(encoding="utf-8")
    ep_tree = ast.parse(ep_stub)
    ep_classes = {node.name for node in ep_tree.body if isinstance(node, ast.ClassDef)}
    assert {"BaseEndpoint", "Endpoint", "AsyncEndpoint"} <= ep_classes


def test_wave6_routes_declared_in_client_pyi_stubs() -> None:
    """Confirm every new route is declared on both Client and AsyncClient in client.pyi."""
    spec = importlib.util.find_spec("mailjet_rest")
    assert spec is not None and spec.origin is not None
    stub_text = (Path(spec.origin).resolve().parent / "client.pyi").read_text(encoding="utf-8")
    new_routes = (
        "send_v31",
        "contacts",
        "v1_templates",
        "template_contents_lock",
        "template_contents_publish",
        "template_contents_unlock",
        "data_images_by_type",
    )
    for route in new_routes:
        assert f"def {route}(self) -> Endpoint: ..." in stub_text
        assert f"def {route}(self) -> AsyncEndpoint: ..." in stub_text
