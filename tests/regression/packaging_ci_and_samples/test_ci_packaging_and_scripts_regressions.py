"""Regression tests for CI workflows, Conda/wheel packaging, ClusterFuzzLite, scripts, and stubs."""

from __future__ import annotations

import ast
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

    source_files = re.search(r"\n  source_files:\n(.*?)(?=\n  requires:)", meta, flags=re.DOTALL)
    assert source_files is not None
    sf_block = source_files.group(1)
    assert "- tests/fuzz/" in sf_block
    assert "tests/fuzz/fuzz_*.py" not in sf_block


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


def test_commit_checks_enables_native_win_arm64_and_linux_arm64_without_prism_emulation() -> None:
    """commit_checks.yaml defines native ARM64 CI job (windows-11-arm + ubuntu-24.04-arm) with Prism guard."""
    ci_yml = (REPO_ROOT / ".github/workflows/commit_checks.yaml").read_text(encoding="utf-8")
    assert "arm64-native:" in ci_yml
    assert "windows-11-arm" in ci_yml
    assert "ubuntu-24.04-arm" in ci_yml
    assert "architecture: 'arm64'" in ci_yml or 'architecture: "arm64"' in ci_yml
    assert "platform.machine().upper()" in ci_yml
    assert "ARM64" in ci_yml
    assert "AARCH64" in ci_yml
    # Must NOT put windows-11-arm into the py3.10..py3.15 Conda matrix (Anaconda win-arm64 starts at py>=3.12)
    conda_matrix = re.search(r"os:\s*\[([^\]]+)\]", ci_yml)
    assert conda_matrix is not None
    assert "windows-11-arm" not in conda_matrix.group(1)


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


# ==========================================
# CodeQL & Code Quality Bot Hygiene Gate (PR #179)
# ==========================================


def _extract_module_all_exports(tree: ast.Module) -> set[str]:
    exports: set[str] = set()
    for stmt in tree.body:
        target_names: list[str] = []
        value: ast.expr | None = None
        if isinstance(stmt, ast.Assign):
            target_names = [t.id for t in stmt.targets if isinstance(t, ast.Name)]
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
            target_names = [stmt.target.id]
            value = stmt.value
        if "__all__" in target_names and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
            for elt in value.elts:
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                    exports.add(elt.value)
    return exports


def _assigned_module_level_globals(stmt: ast.stmt) -> list[tuple[str, int]]:
    if isinstance(stmt, ast.Assign):
        return [(target.id, stmt.lineno) for target in stmt.targets if isinstance(target, ast.Name)]
    if isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name):
        ann = stmt.annotation
        if isinstance(ann, ast.Name) and ann.id == "TypeAlias":
            return []
        if stmt.value is not None:
            return [(stmt.target.id, stmt.lineno)]
    return []


def _scan_file_codeql_hygiene(py_file: Path) -> list[str]:
    rel = py_file.relative_to(REPO_ROOT).as_posix()
    src = py_file.read_text(encoding="utf-8")
    lines = src.splitlines()
    tree = ast.parse(src, filename=str(py_file))

    known_subpkgs = {
        f"mailjet_rest.{p.stem}"
        for p in (REPO_ROOT / "mailjet_rest").iterdir()
        if (p.is_file() and p.suffix == ".py" and p.name != "__init__.py")
        or (p.is_dir() and (p / "__init__.py").is_file())
    }
    imported_modules: dict[str, int] = {}
    import_from_modules: dict[str, int] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                imported_modules.setdefault(alias.name, node.lineno)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            import_from_modules.setdefault(node.module, node.lineno)
            for alias in node.names:
                candidate_submod = f"{node.module}.{alias.name}"
                if candidate_submod in known_subpkgs:
                    imported_modules.setdefault(candidate_submod, node.lineno)
    findings: list[str] = [
        f"{rel}:{imported_modules[mod_name]} & :{import_from_modules[mod_name]} py/import-and-import-from ({mod_name})"
        for mod_name in sorted(set(imported_modules) & set(import_from_modules))
    ]

    findings.extend(
        f"{rel}:{sub.lineno} py/asserts-side-effect in finally block"
        for node in ast.walk(tree)
        if isinstance(node, ast.Try)
        for fin_stmt in node.finalbody
        for sub in ast.walk(fin_stmt)
        if isinstance(sub, ast.Assert) and any(isinstance(expr, (ast.Call, ast.Await)) for expr in ast.walk(sub.test))
    )

    if py_file.name != "__init__.py":
        exports = _extract_module_all_exports(tree)
        loaded_names = {
            node.id for node in ast.walk(tree) if isinstance(node, ast.Name) and isinstance(node.ctx, ast.Load)
        }
        for stmt in tree.body:
            for name, lineno in _assigned_module_level_globals(stmt):
                if (
                    name in exports
                    or name == "_"
                    or "unused" in name.lower()
                    or name == "pytestmark"
                    or (name.startswith("__") and name.endswith("__"))
                ):
                    continue
                if name not in loaded_names:
                    findings.append(f"{rel}:{lineno} py/unused-global-variable ({name})")

    for node in ast.walk(tree):
        if isinstance(node, ast.ExceptHandler) and len(node.body) == 1 and isinstance(node.body[0], ast.Pass):
            end_line = getattr(node.body[0], "end_lineno", node.body[0].lineno)
            snippet = "\n".join(lines[max(0, node.lineno - 1) : end_line])
            if "#" not in snippet:
                findings.append(f"{rel}:{node.lineno} py/empty-except (missing comment)")

    return findings


def test_codeql_import_and_unused_global_hygiene_across_repo() -> None:
    """PR #179 bot gate: forbid py/import-and-import-from, py/unused-global-variable, and commentless py/empty-except."""
    scan_roots = ("mailjet_rest", "tests", "scripts", "samples")
    all_findings: list[str] = []
    for root_name in scan_roots:
        root_dir = REPO_ROOT / root_name
        if not root_dir.is_dir():
            continue
        for py_file in sorted(root_dir.rglob("*.py")):
            if "__pycache__" in py_file.parts:
                continue
            all_findings.extend(_scan_file_codeql_hygiene(py_file))

    assert not all_findings, "CodeQL/Code Quality hygiene violations detected:\n" + "\n".join(all_findings)


def _with_item_is_pytest_raises(with_stmt: ast.With | ast.AsyncWith) -> bool:
    for item in with_stmt.items:
        expr = item.context_expr
        if (
            isinstance(expr, ast.Call)
            and isinstance(expr.func, ast.Attribute)
            and isinstance(expr.func.value, ast.Name)
            and expr.func.value.id == "pytest"
            and expr.func.attr == "raises"
        ):
            return True
    return False


def _body_has_direct_unconditional_raise(stmts: list[ast.stmt]) -> bool:
    for stmt in stmts:
        if isinstance(stmt, ast.Raise):
            return True
        if isinstance(stmt, (ast.With, ast.AsyncWith)) and _body_has_direct_unconditional_raise(stmt.body):
            return True
    return False


def _scan_test_file_code_scanning_hygiene(py_file: Path) -> list[str]:
    rel = py_file.relative_to(REPO_ROOT).as_posix()
    src = py_file.read_text(encoding="utf-8")
    tree = ast.parse(src, filename=str(py_file))
    issues: list[str] = []

    for node in ast.walk(tree):
        # #104: __getitem__ raising RuntimeError unconditionally
        if isinstance(node, ast.FunctionDef) and node.name == "__getitem__":
            issues.extend(
                f"{rel}:{sub.lineno} py/unexpected-raise-in-special-method (__getitem__)"
                for sub in ast.walk(node)
                if isinstance(sub, ast.Raise)
                and isinstance(sub.exc, ast.Call)
                and isinstance(sub.exc.func, ast.Name)
                and sub.exc.func.id == "RuntimeError"
            )

        # #103: identical attribute comparison (e.g. ac.contact is ac.contact)
        if isinstance(node, ast.Compare) and len(node.comparators) == 1 and isinstance(node.left, ast.Attribute):
            right = node.comparators[0]
            if isinstance(right, ast.Attribute) and ast.dump(node.left) == ast.dump(right):
                issues.append(f"{rel}:{node.lineno} py/comparison-of-identical-expressions")

        # #102: ternary expression with constant condition
        if isinstance(node, ast.IfExp) and isinstance(node.test, ast.Constant):
            issues.append(f"{rel}:{node.lineno} py/constant-conditional-expression")

        # #95-#98: .delete(...) call inside assert expression
        if isinstance(node, ast.Assert):
            issues.extend(
                f"{rel}:{node.lineno} py/side-effect-in-assert (.delete)"
                for sub in ast.walk(node.test)
                if isinstance(sub, ast.Call) and isinstance(sub.func, ast.Attribute) and sub.func.attr == "delete"
            )

        # #99-#101: with pytest.raises(...) containing unconditional raise followed by sibling statements
        body_lists: list[list[ast.stmt]] = []
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Module)):
            body_lists.append(node.body)
        for stmts in body_lists:
            for idx, stmt in enumerate(stmts[:-1]):
                if (
                    isinstance(stmt, (ast.With, ast.AsyncWith))
                    and _with_item_is_pytest_raises(stmt)
                    and _body_has_direct_unconditional_raise(stmt.body)
                ):
                    issues.append(f"{rel}:{stmts[idx + 1].lineno} py/unreachable-statement after pytest.raises")

    return issues


def test_code_scanning_alerts_92_to_105_regressions() -> None:
    """Lock remediation of Code Scanning alerts #92-#105 (CodeQL Python + Scorecard Pinned-Dependencies)."""
    findings: list[str] = []
    for py_file in sorted((REPO_ROOT / "tests").rglob("*.py")):
        if "__pycache__" in py_file.parts:
            continue
        findings.extend(_scan_test_file_code_scanning_hygiene(py_file))

    # #105: unused MappingProxyType import in test_telemetry_and_client_mutation_contracts.py
    tele_mut_src = (REPO_ROOT / "tests/unit/clients/test_telemetry_and_client_mutation_contracts.py").read_text(
        encoding="utf-8"
    )
    if "MappingProxyType" in tele_mut_src and tele_mut_src.count("MappingProxyType") == 1:
        findings.append("tests/unit/clients/test_telemetry_and_client_mutation_contracts.py: py/unused-import")

    # #94: _SecretPair sensitive-name heuristic logged directly into test_logger.info
    servers_src = (REPO_ROOT / "tests/integration/local_loopback/_servers.py").read_text(encoding="utf-8")
    if "class _SecretPair" in servers_src:
        findings.append("tests/integration/local_loopback/_servers.py: _SecretPair triggers clear-text-logging taint")

    # #92 & #93: OpenSSF Scorecard Pinned-Dependencies on .clusterfuzzlite/{Dockerfile,build.sh}
    dockerfile_src = (REPO_ROOT / ".clusterfuzzlite/Dockerfile").read_text(encoding="utf-8")
    build_sh_src = (REPO_ROOT / ".clusterfuzzlite/build.sh").read_text(encoding="utf-8")
    cflite_reqs = REPO_ROOT / ".clusterfuzzlite/requirements.txt"
    if "--require-hashes" not in dockerfile_src or not cflite_reqs.is_file():
        findings.append(".clusterfuzzlite/Dockerfile: missing --require-hashes pinned requirements.txt (#92)")
    elif "--hash=sha256:" not in cflite_reqs.read_text(encoding="utf-8"):
        findings.append(".clusterfuzzlite/requirements.txt: missing --hash=sha256 entries (#92)")
    build_sh_non_comment = "\n".join(line for line in build_sh_src.splitlines() if not line.lstrip().startswith("#"))
    if re.search(r"\bpip3?\s+install\b", build_sh_non_comment) and "--require-hashes" not in build_sh_non_comment:
        findings.append(".clusterfuzzlite/build.sh: unhashed pip install triggers PinnedDependenciesID (#93)")

    assert not findings, "Code Scanning regressions (#92-#105) detected:\n" + "\n".join(findings)
