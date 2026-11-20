"""Strict TDD regression suite for PR #179 findings (#5, #8, #13, #14d-e, #14g)."""

from __future__ import annotations

import ast
import importlib
import inspect
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest


if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


REPO_ROOT = Path(__file__).resolve().parents[2]
SAMPLES_DIR = REPO_ROOT / "samples"
SAMPLE_SCRIPTS = sorted(p for p in SAMPLES_DIR.glob("*.py") if p.name != "__init__.py")


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


@pytest.mark.parametrize("script_path", SAMPLE_SCRIPTS, ids=[p.stem for p in SAMPLE_SCRIPTS])
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


@pytest.mark.parametrize("script_path", SAMPLE_SCRIPTS, ids=[p.stem for p in SAMPLE_SCRIPTS])
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


def test_content_api_sample_imports_with_token_only_and_avoids_name_error_and_secret_leak() -> None:
    """content_api_sample supports token-only imports, optional client injection, and never logs bearer_token[:10]."""
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


def test_webhooks_sample_clean_of_harness_constant_and_runs_offline_demo() -> None:
    """webhooks_sample must not leak MAX_HOOK_OUTPUT_CHARS and verify_webhook_demo runs offline."""
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
# Issue #8: Security CI & Pre-Commit Dependency Audit
# ==========================================


def test_security_workflow_audits_installed_package_extras_in_isolated_venv() -> None:
    """security.yml dependency-audit creates .audit-venv, installs extras, and runs pip-audit against it."""
    sec_yml = (REPO_ROOT / ".github/workflows/security.yml").read_text(encoding="utf-8")
    assert ".audit-venv" in sec_yml
    assert ".[async,speedups,tests,linting]" in sec_yml
    assert ".audit-venv/bin/python" in sec_yml
    assert "pip-audit" in sec_yml
    assert "--strict" in sec_yml
    assert "--skip-editable" in sec_yml
    # pip-audit 2.10.1 rejects --python CLI flag; ensure PIPAPI_PYTHON_LOCATION is used instead of broken --python
    assert "PIPAPI_PYTHON_LOCATION" in sec_yml
    assert "pip-audit --strict --skip-editable --python" not in sec_yml


def test_pre_commit_pip_audit_declares_sdk_runtime_and_optional_dependencies() -> None:
    """pre-commit pip-audit hook declares SDK dependencies so it audits real dependency trees."""
    pre_commit = (REPO_ROOT / ".pre-commit-config.yaml").read_text(encoding="utf-8")
    hook_match = re.search(
        r"id:\s*pip-audit.*?(?=\n\s*-\s*repo:|\Z)",
        pre_commit,
        flags=re.DOTALL,
    )
    assert hook_match is not None
    hook_block = hook_match.group(0)
    assert "requests>=2.33.0" in hook_block
    assert "httpx2>=2.0.0" in hook_block
    assert "orjson>=3.10.0" in hook_block


# ==========================================
# Issue #13: Packaging, Release, ClusterFuzzLite, Scripts & .gitignore
# ==========================================


def test_conda_meta_yaml_optional_httpx2_and_git_describe_tag() -> None:
    """conda.recipe/meta.yaml constrains httpx2 as optional and supports GIT_DESCRIBE_TAG."""
    meta = (REPO_ROOT / "conda.recipe/meta.yaml").read_text(encoding="utf-8")
    assert "GIT_DESCRIBE_TAG" in meta
    assert "run_constrained:" in meta

    # Verify httpx2 is NOT in mandatory requirements.run
    run_section = re.search(r"\n  run:\n(.*?)(?=\n  run_constrained:|\ntest:)", meta, flags=re.DOTALL)
    assert run_section is not None
    assert "httpx2" not in run_section.group(1)

    constrained_section = re.search(r"\n  run_constrained:\n(.*?)(?=\ntest:)", meta, flags=re.DOTALL)
    assert constrained_section is not None
    assert "httpx2 >=2.0.0" in constrained_section.group(1)

    test_requires = re.search(r"\n  requires:\n(.*?)(?=\n  commands:)", meta, flags=re.DOTALL)
    assert test_requires is not None
    assert "httpx2 >=2.0.0" in test_requires.group(1)


def test_conda_environment_files_clean_of_selectors_and_aligned_with_pyproject() -> None:
    """environment*.yaml omit broken conda-build selectors and match pyproject.toml dependency floors."""
    env_yaml = (REPO_ROOT / "environment.yaml").read_text(encoding="utf-8")
    assert "httpx2" not in env_yaml
    assert "# [py<312]" not in env_yaml

    env_fuzz = (REPO_ROOT / "environment-fuzz.yaml").read_text(encoding="utf-8")
    assert "libstdcxx-devel_linux-64" not in env_fuzz
    assert "# [linux]" not in env_fuzz

    env_dev = (REPO_ROOT / "environment-dev.yaml").read_text(encoding="utf-8")
    assert "# [py<312]" not in env_dev
    assert "coverage >=7.16.2" in env_dev
    assert "scalene >=2.4.0" in env_dev
    assert "orjson >=3.10.0" in env_dev


def test_clusterfuzzlite_build_sh_and_dockerfile_hardened() -> None:
    """build.sh resolves dict next to fuzzer, isolates PYINSTALLER_CONFIG_DIR, and drops broken jobs pipe."""
    build_sh = (REPO_ROOT / ".clusterfuzzlite/build.sh").read_text(encoding="utf-8")
    assert "${SRC}/tests/fuzz/fuzzer.dict" not in build_sh
    assert '$(dirname -- "${fuzzer}")/fuzzer.dict' in build_sh
    assert "PYINSTALLER_CONFIG_DIR=" in build_sh
    assert "$(jobs -rp | wc -l)" not in build_sh
    assert "kill -0" in build_sh
    assert "${SRC}/mailjet-apiv3-python/tests/fuzz" in build_sh
    assert "tests/fuzz/fuzzer.dict" in build_sh

    dockerfile = (REPO_ROOT / ".clusterfuzzlite/Dockerfile").read_text(encoding="utf-8")
    assert "useradd" not in dockerfile
    assert "chown -R fuzzer:fuzzer /usr/local" not in dockerfile


def test_publish_workflow_sbom_provenance_dispatch_and_wheel_manifest() -> None:
    """publish.yml handles workflow_dispatch, clean SBOM venv, build-job provenance, and full wheel check."""
    publish_yml = (REPO_ROOT / ".github/workflows/publish.yml").read_text(encoding="utf-8")

    # workflow_dispatch safety: SETUPTOOLS_SCM_PRETEND_VERSION gated on refs/tags/v
    assert "refs/tags/v" in publish_yml
    assert "SETUPTOOLS_SCM_PRETEND_VERSION" in publish_yml
    assert (
        re.search(r"GITHUB_REF:\s*\$\{\{\s*github\.ref\s*\}\}.*?refs/tags/v", publish_yml, flags=re.DOTALL) is not None
    )

    # Clean SBOM venv without pip
    assert "python -m venv --without-pip .sbom-target-venv" in publish_yml
    assert "--python .sbom-target-venv/bin/python" in publish_yml

    # SLSA provenance runs inside build job BEFORE publish job
    build_job_match = re.search(r"\n  build:\n(.*?)\n  publish:\n", publish_yml, flags=re.DOTALL)
    publish_job_match = re.search(r"\n  publish:\n(.*)", publish_yml, flags=re.DOTALL)
    assert build_job_match is not None and publish_job_match is not None
    build_job = build_job_match.group(1)
    publish_job = publish_job_match.group(1)
    assert "actions/attest-build-provenance@" in build_job
    assert "actions/attest-build-provenance@" not in publish_job
    assert "id-token: write" in build_job
    assert "attestations: write" in build_job

    # Anchored exact verification covering ALL 23 tracked mailjet_rest files
    assert "unzip -Z1" in publish_yml
    assert "grep -Fxq" in publish_yml
    expected_pkg_files = sorted(
        p.relative_to(REPO_ROOT).as_posix()
        for p in (REPO_ROOT / "mailjet_rest").rglob("*")
        if p.is_file() and "__pycache__" not in p.parts
    )
    assert len(expected_pkg_files) >= 21
    for rel_path in expected_pkg_files:
        assert f'"{rel_path}"' in publish_yml, f"publish.yml wheel check missing {rel_path}"


def test_cflite_workflows_permissions_sarif_and_dependabot_docker() -> None:
    """cflite workflows use least-privilege permissions & SARIF upload; dependabot includes docker."""
    batch_yml = (REPO_ROOT / ".github/workflows/cflite_batch.yml").read_text(encoding="utf-8")
    assert "permissions: read-all" not in batch_yml
    assert "contents: read" in batch_yml
    assert "security-events: write" in batch_yml
    assert "github/codeql-action/upload-sarif@" in batch_yml
    assert "cifuzz-sarif/results.sarif" in batch_yml

    pr_yml = (REPO_ROOT / ".github/workflows/cflite_pr.yml").read_text(encoding="utf-8")
    assert "security-events: write" in pr_yml
    assert "github/codeql-action/upload-sarif@" in pr_yml
    assert "cifuzz-sarif/results.sarif" in pr_yml

    dependabot = (REPO_ROOT / ".github/dependabot.yml").read_text(encoding="utf-8")
    assert "docker" in dependabot
    assert "/.clusterfuzzlite" in dependabot


def test_manage_sh_and_gitignore_hardening() -> None:
    """manage.sh fixes subshell jobs pipe & prunes venvs in clean; .gitignore keeps .mesh/ + ignores sbom."""
    manage_sh = (REPO_ROOT / "manage.sh").read_text(encoding="utf-8")
    assert "$(jobs -rp | wc -l)" not in manage_sh
    assert "kill -0" in manage_sh
    assert "-path './.venv'" in manage_sh
    assert "-path './venv'" in manage_sh
    assert "-prune" in manage_sh

    gitignore_lines = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8").splitlines()
    assert ".mesh/" in gitignore_lines
    assert "sbom/" in gitignore_lines
    assert ".sbom-*-venv/" in gitignore_lines


# ==========================================
# Issue #14d-e, #14g: CI Matrix, Ruff/Mutmut Config, Docs & Metrics
# ==========================================


def test_commit_checks_runs_local_https_speedups_and_sync_only_leg() -> None:
    """commit_checks.yaml runs local HTTPS integration, [speedups] orjson tests, and sync-only leg."""
    ci_yml = (REPO_ROOT / ".github/workflows/commit_checks.yaml").read_text(encoding="utf-8")
    assert "tests/integration/test_local_https_integration.py" in ci_yml
    assert "speedups" in ci_yml
    assert "httpx2" in ci_yml
    assert "pip uninstall -y httpx2" in ci_yml or "without" in ci_yml.lower()


def test_pyproject_ruff_includes_tests_and_mutmut_covers_security_modules() -> None:
    """pyproject.toml lints tests/ with Ruff and mutmut covers client + security utilities."""
    if tomllib is None:
        pytest.skip("tomllib/tomli unavailable on Python 3.10")
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    extend_exclude = data["tool"]["ruff"]["extend-exclude"]
    assert "tests" not in extend_exclude

    tests_ignores = set(data["tool"]["ruff"]["lint"]["extend-per-file-ignores"]["tests/*"])
    assert {"S", "SLF", "PL"} <= tests_ignores

    only_mutate = set(data["tool"]["mutmut"]["only_mutate"])
    required_mutmut = {
        "mailjet_rest/client.py",
        "mailjet_rest/utils/guardrails.py",
        "mailjet_rest/utils/filesystem_security.py",
        "mailjet_rest/utils/html_guard.py",
        "mailjet_rest/utils/telemetry.py",
    }
    assert required_mutmut <= only_mutate


def test_readme_accurate_types_tls_adapter_and_patch_examples() -> None:
    """README.md avoids SendV3Payload typo, raw HTTPAdapter TLS stripping, and invalid contact.patch."""
    readme = (REPO_ROOT / "README.md").read_text(encoding="utf-8")
    assert "SendV3Payload" not in readme
    assert "from requests.adapters import HTTPAdapter" not in readme
    assert re.search(r"(?<!Secure)HTTPAdapter\(", readme) is None
    assert "SecureHTTPAdapter" in readme
    assert "Config(max_retries=" in readme
    assert "mailjet.contact.patch(" not in readme
    assert "v1_templates.patch(" in readme

    async_sample_ref = next(
        (line for line in readme.splitlines() if "samples/async_client_sample.py" in line),
        "",
    )
    assert async_sample_ref != ""
    assert "patch()" not in async_sample_ref
    assert "update()" in async_sample_ref


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
