"""Regression tests for CI workflows, Conda/wheel packaging, ClusterFuzzLite, scripts, and stubs."""

from __future__ import annotations

import importlib.util
import os
import re
import shlex
import subprocess
import sys
from pathlib import Path

import pytest

from tests.regression.conftest import REPO_ROOT


if sys.version_info >= (3, 11):
    import tomllib
else:  # pragma: no cover - Python 3.10 fallback
    try:
        import tomli as tomllib
    except ModuleNotFoundError:
        tomllib = None  # type: ignore[assignment]


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
# Issue #14d-e, #14g: CI Matrix, Ruff/Mutmut Config, Scripts & Stubs
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


def test_manage_sh_fuzz_all_launches_all_fuzzers_by_default_and_honors_fuzz_jobs(tmp_path: Path) -> None:
    """manage.sh fuzz_all must launch all fuzzers concurrently by default, honor FUZZ_JOBS, and validate it."""
    manage_src = (REPO_ROOT / "manage.sh").read_text(encoding="utf-8")
    assert 'max_jobs="${FUZZ_JOBS:-${total_fuzzers}}"' in manage_src
    assert "FUZZ_JOBS:-3" not in manage_src
    assert "kill -0" in manage_src

    if sys.platform == "win32":
        return

    sandbox = tmp_path / "repo"
    fuzz_dir = sandbox / "tests" / "fuzz"
    fuzz_dir.mkdir(parents=True)
    (fuzz_dir / "fuzzer.dict").write_text('token_a="abc"\n', encoding="utf-8", newline="\n")

    manage_copy = sandbox / "manage.sh"
    manage_copy.write_text(manage_src, encoding="utf-8", newline="\n")
    manage_copy.chmod(0o755)

    for idx in range(1, 7):
        (fuzz_dir / f"fuzz_0{idx}.py").write_text(
            "import pathlib, sys, time\n"
            "time.sleep(0.15)\n"
            "pathlib.Path('ran.ok').write_text(sys.argv[0], encoding='utf-8')\n",
            encoding="utf-8",
            newline="\n",
        )

    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    nproc_bin = bin_dir / "nproc"
    nproc_bin.write_text("#!/usr/bin/env bash\necho 2\n", encoding="utf-8", newline="\n")
    nproc_bin.chmod(0o755)

    py_bin = bin_dir / "python"
    py_bin.write_text(
        "#!/usr/bin/env bash\n"
        'if [[ "${1:-}" == "-c" && "${2:-}" == *"import atheris"* ]]; then\n'
        "    exit 0\n"
        "fi\n"
        f'exec {shlex.quote(sys.executable)} "$@"\n',
        encoding="utf-8",
        newline="\n",
    )
    py_bin.chmod(0o755)

    base_env = os.environ.copy()
    base_env["PATH"] = f"{bin_dir}:{base_env.get('PATH', '')}"
    base_env.pop("FUZZ_JOBS", None)

    # Case A: FUZZ_JOBS unset -> ignores nproc=2 and launches all 6 fuzzers concurrently
    proc_a = subprocess.run(
        ["bash", str(manage_copy), "fuzz_all", "1"],
        cwd=str(sandbox),
        env=base_env,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc_a.returncode == 0, f"Case A failed:\nSTDOUT:\n{proc_a.stdout}\nSTDERR:\n{proc_a.stderr}"
    assert "max parallel jobs: 6" in proc_a.stdout
    for idx in range(1, 7):
        assert f"[{idx}/6] Running fuzzer: fuzz_0{idx}" in proc_a.stdout
        assert (sandbox / "logs" / f"fuzz_0{idx}" / "ran.ok").is_file()
        (sandbox / "logs" / f"fuzz_0{idx}" / "ran.ok").unlink()

    # Case B: FUZZ_JOBS=2 -> completes all 6 fuzzers across 3 waves
    env_b = base_env.copy()
    env_b["FUZZ_JOBS"] = "2"
    proc_b = subprocess.run(
        ["bash", str(manage_copy), "fuzz_all", "1"],
        cwd=str(sandbox),
        env=env_b,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc_b.returncode == 0, f"Case B failed:\nSTDOUT:\n{proc_b.stdout}\nSTDERR:\n{proc_b.stderr}"
    assert "max parallel jobs: 2" in proc_b.stdout
    for idx in range(1, 7):
        assert (sandbox / "logs" / f"fuzz_0{idx}" / "ran.ok").is_file()

    # Case C: FUZZ_JOBS=0 -> fails fast with validation message
    env_c = base_env.copy()
    env_c["FUZZ_JOBS"] = "0"
    proc_c = subprocess.run(
        ["bash", str(manage_copy), "fuzz_all", "1"],
        cwd=str(sandbox),
        env=env_c,
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )
    assert proc_c.returncode != 0
    assert "FUZZ_JOBS must be a positive integer" in (proc_c.stdout + proc_c.stderr)


# ==========================================
# Issue #12d: Stub Generation AST Extraction
# ==========================================


def test_check_stubs_extracts_classvars_all_and_overloads_from_ast(tmp_path: Path) -> None:
    """PR #179 #12d: check_stubs.py must extract BaseClient ClassVars, __all__, reserved_attrs, and @overload from AST."""
    script_path = REPO_ROOT / "scripts" / "check_stubs.py"
    spec = importlib.util.spec_from_file_location("check_stubs_under_test", script_path)
    assert spec is not None and spec.loader is not None
    check_stubs = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(check_stubs)

    pkg_dir = Path(check_stubs._default_package_dir()).resolve()
    client_stub = (pkg_dir / "client.pyi").read_text(encoding="utf-8")
    for class_var in ("_TRANSIENT_STATUS_CODES", "_MAX_RETRY_DELAY", "_RETRY_ALLOWED_METHODS"):
        assert f"{class_var}: ClassVar[" in client_stub

    # Dynamic AST test on an isolated temporary package copy
    pkg_copy = tmp_path / "mailjet_rest"
    pkg_copy.mkdir()
    for fname in ("client.py", "endpoint.py", "routes.py"):
        (pkg_copy / fname).write_text((pkg_dir / fname).read_text(encoding="utf-8"), encoding="utf-8")

    # Inject an extra ClassVar + @overload method + updated __all__ export into copied client.py
    copied_client = (pkg_copy / "client.py").read_text(encoding="utf-8")
    copied_client = copied_client.replace(
        '"parse_response",\n]',
        '"parse_response",\n    "_ExtraStubExport",\n]',
    )
    copied_client = copied_client.replace(
        "_RETRY_STRATEGY: ClassVar[JitterRetry] = DEFAULT_RETRY_STRATEGY",
        "_RETRY_STRATEGY: ClassVar[JitterRetry] = DEFAULT_RETRY_STRATEGY\n    _AST_PROBE_VAR: ClassVar[int] = 42",
    )
    copied_client = copied_client.replace(
        "    def ping(self, timeout: TimeoutType = None) -> bool:",
        "    @overload\n"
        "    def overloaded_probe(self, x: int) -> int: ...\n"
        "    @overload\n"
        "    def overloaded_probe(self, x: str) -> str: ...\n"
        "    def overloaded_probe(self, x: int | str) -> int | str:\n"
        "        return x\n\n"
        "    def ping(self, timeout: TimeoutType = None) -> bool:",
    )
    (pkg_copy / "client.py").write_text(copied_client, encoding="utf-8")

    generated = check_stubs.render_client_stub(pkg_copy)
    assert "_AST_PROBE_VAR: ClassVar[int]" in generated
    assert '"_ExtraStubExport",' in generated
    assert "@overload\n    def overloaded_probe(self, x: int) -> int: ..." in generated
    assert "@overload\n    def overloaded_probe(self, x: str) -> str: ..." in generated
    assert "def overloaded_probe(self, x: int | str)" not in generated
