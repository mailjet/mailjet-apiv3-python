"""Regression tests for sample scripts, README, CHANGELOG, and PERFORMANCE documentation."""

from __future__ import annotations

import ast
import importlib
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any, get_args
from unittest.mock import MagicMock

import pytest

from mailjet_rest.client import BaseClient
from mailjet_rest.endpoint import AsyncEndpoint, Endpoint
from mailjet_rest.testing import MockEndpoint
from mailjet_rest.types import HttpMethod
from mailjet_rest.utils.retry import RETRY_ALLOWED_METHODS
from tests.regression.conftest import REPO_ROOT, SAMPLES_DIR


_SAMPLE_FILES: list[Path] = sorted(p for p in SAMPLES_DIR.glob("*.py") if p.name != "__init__.py")


def _clean_credential_env(**overrides: str) -> dict[str, str]:
    env = os.environ.copy()
    for key in ("MJ_APIKEY_PUBLIC", "MJ_APIKEY_PRIVATE", "MJ_CONTENT_TOKEN"):
        env.pop(key, None)
    env["PYTHONPATH"] = str(REPO_ROOT)
    env.update(overrides)
    return env


# ==========================================
# Issue #5: Sample Scripts Startup, Content API & Webhooks Hygiene
# ==========================================


@pytest.mark.parametrize("script_path", _SAMPLE_FILES, ids=[p.stem for p in _SAMPLE_FILES])
def test_sample_module_imports_cleanly_without_credentials(script_path: Path) -> None:
    """Every samples/*.py module imports cleanly with zero credentials set."""
    mod_name = f"samples.{script_path.stem}"
    proc = subprocess.run(
        [sys.executable, "-c", "import importlib, sys; importlib.import_module(sys.argv[1])", mod_name],
        cwd=str(REPO_ROOT),
        env=_clean_credential_env(),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, f"Importing {mod_name} failed:\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"


@pytest.mark.parametrize("script_path", _SAMPLE_FILES, ids=[p.stem for p in _SAMPLE_FILES])
def test_sample_script_executes_directly_without_credentials(script_path: Path, tmp_path: Path) -> None:
    """Executing every samples/*.py directly exits 0 cleanly even from an unrelated cwd without credentials."""
    env = os.environ.copy()
    for key in ("MJ_APIKEY_PUBLIC", "MJ_APIKEY_PRIVATE", "MJ_CONTENT_TOKEN", "PYTHONPATH"):
        env.pop(key, None)

    proc = subprocess.run(
        [sys.executable, str(script_path)],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, (
        f"Executing {script_path.name} failed (rc={proc.returncode}):\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}"
    )
    assert "Traceback" not in proc.stderr


def test_content_api_sample_imports_with_token_only_and_avoids_name_error_and_secret_leak(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """content_api_sample supports token-only imports, optional client injection, and never logs bearer_token[:10]."""
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    sample_path = SAMPLES_DIR / "content_api_sample.py"
    source = sample_path.read_text(encoding="utf-8")

    # Never log token prefix (CWE-532)
    assert "bearer_token[:10]" not in source
    assert "bearer_token[:" not in source

    # Token-only environment import must not crash requiring MJ_APIKEY_PUBLIC/PRIVATE
    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import importlib, sys; importlib.import_module(sys.argv[1])",
            "samples.content_api_sample",
        ],
        cwd=str(REPO_ROOT),
        env=_clean_credential_env(MJ_CONTENT_TOKEN="dummy_content_token_value"),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, f"Import with MJ_CONTENT_TOKEN failed:\n{proc.stderr}"

    mod: Any = importlib.import_module("samples.content_api_sample")
    assert hasattr(mod, "_get_content_client")
    assert callable(mod._get_content_client)

    mock_client = MagicMock()
    for fn_name in (
        "generate_token",
        "upload_image",
        "list_v1_templates",
        "publish_template_contents",
        "unlock_template_contents",
        "get_image_by_type",
    ):
        fn = getattr(mod, fn_name)
        sig = inspect.signature(fn)
        assert "client" in sig.parameters, f"{fn_name} must accept optional client parameter"

    mod.generate_token(client=mock_client)
    mod.upload_image(client=mock_client)
    mod.list_v1_templates(client=mock_client)
    mod.publish_template_contents(123, client=mock_client)
    mod.unlock_template_contents(123, client=mock_client)
    mod.get_image_by_type(456, client=mock_client)
    assert mock_client.tokens.create.called
    assert mock_client.data_images.create.called
    assert mock_client.v1_templates.get.called
    assert mock_client.template_contents_publish.create.called
    assert mock_client.template_contents_unlock.create.called
    assert mock_client.data_images_by_type.get.called


def test_webhooks_sample_clean_of_harness_constant_and_runs_offline_demo(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """webhooks_sample must not leak MAX_HOOK_OUTPUT_CHARS and verify_webhook_demo runs offline."""
    monkeypatch.syspath_prepend(str(REPO_ROOT))
    sample_path = SAMPLES_DIR / "webhooks_sample.py"
    source = sample_path.read_text(encoding="utf-8")
    assert "MAX_HOOK_OUTPUT_CHARS" not in source

    mod: Any = importlib.import_module("samples.webhooks_sample")
    assert not hasattr(mod, "MAX_HOOK_OUTPUT_CHARS")
    assert mod.verify_webhook_demo() is True

    proc = subprocess.run(
        [sys.executable, str(sample_path)],
        cwd=str(REPO_ROOT),
        env=_clean_credential_env(),
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0
    assert "verify_webhook_demo: True" in proc.stdout


def test_new_sample_imports_contacts_sample_from_unrelated_cwd(tmp_path: Path) -> None:
    """new_sample resolves samples.contacts_sample without ModuleNotFoundError from any cwd."""
    script_path = SAMPLES_DIR / "new_sample.py"
    env = os.environ.copy()
    for key in ("MJ_APIKEY_PUBLIC", "MJ_APIKEY_PRIVATE", "MJ_CONTENT_TOKEN", "PYTHONPATH"):
        env.pop(key, None)

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            (
                "import importlib.util, sys; "
                "spec = importlib.util.spec_from_file_location('new_sample', sys.argv[1]); "
                "mod = importlib.util.module_from_spec(spec); "
                "spec.loader.exec_module(mod); "
                "fn = mod._load_edit_contact_data(); "
                "assert callable(fn)"
            ),
            str(script_path),
        ],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, f"new_sample import loader failed:\n{proc.stderr}"


# ==========================================
# Issue #14d-e, #14g: Docs, Metrics & Windows cp1252 Smoke Runner
# ==========================================


def test_readme_accurate_types_tls_adapter_and_patch_examples() -> None:
    """README.md avoids SendV3Payload typo, raw HTTPAdapter TLS stripping, and removed PATCH section."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "SendV3Payload" not in readme
    assert "from requests.adapters import HTTPAdapter" not in readme
    assert re.search(r"(?<!Secure)HTTPAdapter\(", readme) is None
    assert "SecureHTTPAdapter" in readme
    assert "Config(max_retries=" in readme
    assert "mailjet.contact.patch(" not in readme
    assert "v1_templates.patch(" not in readme
    assert "#### PATCH (Partial Update)" not in readme
    assert "#patch-partial-update" not in readme
    assert "### Standard REST Actions (GET, POST, PUT, DELETE)" in readme
    assert "(#standard-rest-actions-get-post-put-delete)" in readme
    assert "`client.send_v31` (`POST /v3.1/send`)" in readme

    async_sample_ref = next(
        (line for line in readme.splitlines() if "samples/async_client_sample.py" in line),
        "",
    )
    assert async_sample_ref != ""
    assert "patch()" not in async_sample_ref
    assert "update()" in async_sample_ref


def test_sdk_and_docs_omit_unsupported_patch_method() -> None:
    """SDK core, types, retry policy, endpoints, mocks, and README Idempotency bullet omit unsupported HTTP PATCH."""
    assert BaseClient._MUTATING_METHODS == frozenset({"POST", "PUT", "DELETE"})
    assert "PATCH" not in BaseClient._MUTATING_METHODS
    assert "PATCH" not in RETRY_ALLOWED_METHODS
    assert get_args(HttpMethod) == ("GET", "POST", "PUT", "DELETE")
    assert not hasattr(Endpoint, "patch")
    assert not hasattr(AsyncEndpoint, "patch")
    assert not hasattr(MockEndpoint, "patch")

    endpoint_pyi = (REPO_ROOT / "mailjet_rest/endpoint.pyi").read_text(encoding="utf-8")
    assert "def patch(" not in endpoint_pyi

    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    idempotency_line = next(
        (line for line in readme.splitlines() if "**Idempotency Fingerprinting:**" in line),
        "",
    )
    assert idempotency_line != ""
    assert "(`POST`, `PUT`, and `DELETE`)" in idempotency_line
    assert "PATCH" not in idempotency_line
    assert "A `PUT` request in the Mailjet API will work as a `PATCH` request" in readme


def test_changelog_and_performance_metrics_consistent_with_codebase() -> None:
    """CHANGELOG.md and PERFORMANCE.md reflect actual types.py counts, slotscheck counts, and post-fix timings."""
    types_src = (REPO_ROOT / "mailjet_rest/types.py").read_text(encoding="utf-8")
    tree = ast.parse(types_src)
    alias_count = sum(
        1
        for node in tree.body
        if isinstance(node, ast.AnnAssign) and getattr(node.annotation, "id", None) == "TypeAlias"
    )
    td_count = sum(1 for node in tree.body if isinstance(node, ast.ClassDef))
    assert alias_count == 18
    assert td_count == 17

    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    performance = (REPO_ROOT / "PERFORMANCE.md").read_text(encoding="utf-8")

    assert f"`{alias_count}` type aliases" in changelog
    assert f"`{td_count}` OpenAPI `TypedDict`" in changelog
    assert "`53` classes" in changelog
    assert "`53` classes scanned across `20` modules" in performance

    # Stale pre-Issue-#10 slowdown metrics must be updated
    assert "`635.2 ns`" not in performance
    assert "`10.08 µs`" not in performance


def test_smoke_readme_runner_executes_under_cp1252_encoding(tmp_path: Path) -> None:
    """samples/smoke_readme_runner.py must run under Windows cp1252 stdout encoding without UnicodeEncodeError."""
    env = _clean_credential_env(PYTHONIOENCODING="cp1252", PYTHONUTF8="0")
    env.pop("PYTHONPATH", None)
    proc = subprocess.run(
        [sys.executable, str(SAMPLES_DIR / "smoke_readme_runner.py")],
        cwd=str(tmp_path),
        env=env,
        capture_output=True,
        text=True,
        encoding="cp1252",
        timeout=20,
        check=False,
    )
    assert proc.returncode == 0, f"smoke_readme_runner failed under cp1252:\nSTDERR:\n{proc.stderr}"
    assert "UnicodeEncodeError" not in proc.stderr
