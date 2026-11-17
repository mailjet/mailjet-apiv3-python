#!/usr/bin/env bash

set -euo pipefail
set -E
shopt -s inherit_errexit 2>/dev/null || true

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
cd -- "${SCRIPT_DIR}"

# ==============================================================================
# GLOBAL VARIABLES & SETUP
# ==============================================================================
SRC_DIR="mailjet_rest"
TEST_DIR="tests"
SCRIPTS_DIR="scripts"
CONDA_ENV_NAME="mailjet-dev"

# Color formatting for terminal output
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m'

info() { echo -e "${CYAN}=> $1${NC}"; }
success() { echo -e "${GREEN}=> $1${NC}"; }
warn() { echo -e "${YELLOW}=> WARNING: $1${NC}"; }
error() { echo -e "${RED}=> ERROR: $1${NC}"; }

# ==============================================================================
# ENVIRONMENT & SETUP
# ==============================================================================
env_setup() {
    info "Creating or updating conda environment '${CONDA_ENV_NAME}'..."
    if conda env list | awk '{print $1}' | grep -Fxq "${CONDA_ENV_NAME}"; then
        conda env update -n "${CONDA_ENV_NAME}" --file environment-dev.yaml
    else
        conda env create -n "${CONDA_ENV_NAME}" -y --file environment-dev.yaml
    fi
    info "Installing package in editable mode..."
    conda run --name "${CONDA_ENV_NAME}" pip install -e ".[linting,tests,build]"
    info "Installing pre-commit hooks..."
    conda run --name "${CONDA_ENV_NAME}" pre-commit install
    success "Environment ready. Activate via: conda activate ${CONDA_ENV_NAME}"
}

# ==============================================================================
# FORMATTING & LINTING
# ==============================================================================
format() {
    info "Formatting code with Ruff..."
    ruff format "${SRC_DIR}" "${TEST_DIR}" "${SCRIPTS_DIR}" samples
    info "Applying safe Ruff fixes..."
    ruff check --fix "${SRC_DIR}" "${TEST_DIR}" "${SCRIPTS_DIR}" samples
    success "Code formatted successfully."
}

lint() {
    info "Running Ruff lint and format checks..."
    ruff check .
    ruff format --check .

    info "Running MyPy strict type checking..."
    mypy --strict "${SRC_DIR}"

    info "Running Pyright type checking..."
    pyright "${SRC_DIR}"

    info "Running slotscheck verification..."
    slotscheck -m "${SRC_DIR}"

    info "Checking tracked .pyi stub synchronization..."
    python "${SCRIPTS_DIR}/check_stubs.py" --check

    info "Running Bandit security scan..."
    bandit -c pyproject.toml -r "${SRC_DIR}"

    if command -v vulture >/dev/null 2>&1; then
        info "Running Vulture dead-code check..."
        vulture "${SRC_DIR}" --min-confidence 80
    fi

    if command -v typos >/dev/null 2>&1; then
        info "Running Typos spell check..."
        typos "${SRC_DIR}" "${TEST_DIR}" README.md
    fi

    success "All linting and static analysis checks passed."
}

# ==============================================================================
# TESTING SCENARIOS
# ==============================================================================
test_all() {
    info "Running ALL tests (Unit + Property + Regression + Integration)..."
    pytest -n auto "${TEST_DIR}" "$@"
}

test_unit() {
    info "Running offline UNIT + PROPERTY + REGRESSION tests..."
    pytest "${TEST_DIR}/unit" "${TEST_DIR}/property" "${TEST_DIR}/regression" "$@"
}

test_integration() {
    info "Running INTEGRATION tests..."
    pytest "${TEST_DIR}/integration" "$@"
}

test_cov() {
    info "Running tests with coverage requirements (fail under 80%)..."
    pytest -n auto --cov="${SRC_DIR}" "${TEST_DIR}/unit" "${TEST_DIR}/property" "${TEST_DIR}/regression" \
        --cov-fail-under=80 --cov-report=term-missing --cov-report=html
    success "Coverage report generated in htmlcov/index.html"
}

test_no_warnings() {
    info "Running tests while ignoring DeprecationWarnings..."
    pytest -W "ignore::DeprecationWarning" "$@"
}

test_strict_warnings() {
    info "Running tests with warnings treated as ERRORS..."
    pytest -W error "${TEST_DIR}/unit" "${TEST_DIR}/property" "${TEST_DIR}/regression" "$@"
}

test_examples() {
    if [[ -z "${MJ_APIKEY_PUBLIC:-}" || -z "${MJ_APIKEY_PRIVATE:-}" ]]; then
        warn "MJ_APIKEY_PUBLIC or MJ_APIKEY_PRIVATE environment variables are not set."
        warn "Live examples may fail without them."
        echo ""
    fi

    export PYTHONPATH="${SCRIPT_DIR}${PYTHONPATH:+:${PYTHONPATH}}"
    info "Starting Mailjet Examples Suite..."

    if [[ ! -d "samples" ]]; then
        warn "Examples directory 'samples' not found. Skipping."
        return 0
    fi

    local script
    for script in samples/*.py; do
        [[ -e "${script}" ]] || continue
        if [[ "$(basename -- "${script}")" == "__init__.py" ]]; then
            continue
        fi
        success "Running: ${script}..."
        python "${script}"
        echo "---------------------------------------------------"
    done

    success "All examples executed successfully."
}

# ==============================================================================
# SECURITY & FUZZING
# ==============================================================================
fuzz_all() {
    local duration="${1:-20}"
    if [[ $# -gt 0 ]]; then
        shift
    fi

    local root_dir="${SCRIPT_DIR}"
    local fuzzer_dir="tests/fuzz"
    local dictionary="tests/fuzz/fuzzer.dict"
    local corpus_dir="tests/fuzz/corpus"
    local log_dir="logs"

    if [[ ! -d "${fuzzer_dir}" ]]; then
        error "Fuzzer directory '${fuzzer_dir}' not found."
        return 1
    fi

    mkdir -p -- "${log_dir}"

    local -a dict_args=()
    if [[ -f "${dictionary}" ]]; then
        dict_args+=("-dict=${root_dir}/${dictionary}")
    else
        warn "Dictionary '${dictionary}' not found. Running without it."
    fi

    info "Starting security fuzzing suite (duration: ${duration}s per fuzzer)..."
    if [[ $# -gt 0 ]]; then
        info "Applying extra LibFuzzer arguments: $*"
    fi

    shopt -s nullglob
    local fuzzers=("${fuzzer_dir}"/fuzz_*.py)
    shopt -u nullglob

    if [[ ${#fuzzers[@]} -eq 0 ]]; then
        error "No fuzzer scripts found in '${fuzzer_dir}'."
        return 1
    fi

    local -a exec_cmd=()
    if [[ "${CONDA_DEFAULT_ENV:-}" == "${CONDA_ENV_NAME}" ]]; then
        exec_cmd=("python")
    else
        exec_cmd=("conda" "run" "--name" "${CONDA_ENV_NAME}" "python")
    fi

    local -a pids=()
    local fuzzer
    for fuzzer in "${fuzzers[@]}"; do
        local fuzzer_name
        fuzzer_name="$(basename -- "${fuzzer}" .py)"

        local fuzzer_work_dir="${root_dir}/${log_dir}/${fuzzer_name}"
        local fuzzer_corpus="${root_dir}/${corpus_dir}/${fuzzer_name}"

        mkdir -p -- "${fuzzer_work_dir}" "${fuzzer_corpus}"
        echo -e "Running fuzzer: ${fuzzer_name} (Logs: logs/${fuzzer_name}/fuzz_output.log)"

        (
            cd -- "${fuzzer_work_dir}"
            "${exec_cmd[@]}" "${root_dir}/${fuzzer}" \
                "${dict_args[@]}" \
                -max_len=512 \
                -timeout=5 \
                -shrink=1 \
                -use_value_profile=1 \
                -max_total_time="${duration}" \
                -artifact_prefix="./" \
                "${fuzzer_corpus}" \
                "$@" > "fuzz_output.log" 2>&1
        ) &
        pids+=("$!")
    done

    info "All fuzzers launched in isolation. Waiting for completion..."
    local status=0
    local pid
    for pid in "${pids[@]}"; do
        if ! wait "${pid}"; then
            status=1
        fi
    done

    if [[ "${status}" -ne 0 ]]; then
        error "One or more fuzzers exited non-zero. Check logs/<fuzzer>/fuzz_output.log"
        return "${status}"
    fi

    success "All fuzz tests finished cleanly."
}

# ==============================================================================
# PERFORMANCE & BENCHMARKING
# ==============================================================================
perf_bench() {
    info "Running pytest-benchmark performance tests..."
    pytest "${TEST_DIR}/test_perf.py" "$@"
}

perf_profile() {
    info "Running cold-boot profiler (cProfile)..."
    python "${TEST_DIR}/test_boot.py"
}

# ==============================================================================
# SECURITY AUDITS & PRE-COMMIT
# ==============================================================================
audit_deps() {
    info "Running pip-audit for known vulnerabilities..."
    if [[ -n "${CONDA_PREFIX:-}" ]]; then
        pip-audit --skip-editable --disable-pip
    else
        pip-audit --strict --skip-editable --disable-pip
    fi

    if command -v osv-scanner >/dev/null 2>&1; then
        info "Running Google OSV-Scanner..."
        osv-scanner -r .
    else
        warn "osv-scanner not found. Skipping."
    fi
}

run_hooks() {
    info "Running all pre-commit hooks..."
    pre-commit run --all-files
}

# ==============================================================================
# BUILD & RELEASE
# ==============================================================================
build_pkg() {
    clean
    info "Building source and wheel distribution..."
    python -m build
    twine check dist/*
    ls -l dist
    success "Build complete."
}

release() {
    build_pkg
    info "Uploading to PyPI via Twine..."
    twine upload dist/*
}

# ==============================================================================
# CLEANUP
# ==============================================================================
clean() {
    info "Cleaning up workspace (caches, builds, coverage)..."

    find . -type d -name '__pycache__' -exec rm -rf {} +
    find . -type f -name '*.py[co]' -exec rm -f {} +
    find . -type f -name '*~' -exec rm -f {} +

    rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .tox/
    rm -rf .coverage htmlcov/ coverage.xml reports/
    rm -rf build/ dist/ .eggs/
    find . -type d -name '*.egg-info' -exec rm -rf {} +
    find . -type f -name '*.egg' -exec rm -f {} +

    rm -rf logs/
    rm -rf mutants/ .mutmut-cache
    rm -f ./*.prof profile.html profile.json tmp.txt wget-log

    success "Workspace cleaned."
}

# ==============================================================================
# MAIN ROUTER & HELP
# ==============================================================================
help() {
    echo -e "${CYAN}Mailjet SDK Management Script${NC}"
    echo "Usage: ./manage.sh <command> [extra_arguments...]"
    echo ""
    echo -e "${YELLOW}Development & Code Quality:${NC}"
    echo "  env_setup            - Create/update conda dev env and install pre-commit"
    echo "  format               - Format code (Ruff)"
    echo "  lint                 - Run linters, type checkers, slotscheck, and bandit"
    echo "  run_hooks            - Run all pre-commit hooks manually"
    echo ""
    echo -e "${YELLOW}Testing:${NC}"
    echo "  test_all             - Run all tests"
    echo "  test_unit            - Run offline unit, property, and regression tests"
    echo "  test_integration     - Run live integration tests"
    echo "  test_cov             - Run offline tests with >=80% coverage gate"
    echo "  test_no_warnings     - Run tests hiding DeprecationWarnings"
    echo "  test_strict_warnings - Run offline tests with warnings as errors"
    echo "  test_examples        - Run sample scripts in samples/"
    echo ""
    echo -e "${YELLOW}Security & Fuzzing:${NC}"
    echo "  fuzz_all             - Run all fuzz tests (duration_s [libfuzzer flags])"
    echo "  audit_deps           - Run pip-audit and osv-scanner (fail closed)"
    echo ""
    echo -e "${YELLOW}Performance & Release:${NC}"
    echo "  perf_bench           - Run pytest-benchmark suite"
    echo "  perf_profile         - Run cProfile on cold boot"
    echo "  clean                - Remove build, test, and cache artifacts"
    echo "  build_pkg            - Build source and wheel package + twine check"
    echo "  release              - Build and upload release to PyPI"
    echo "  help                 - Show this menu"
}

if [[ $# -eq 0 ]]; then
    help
    exit 1
fi

COMMAND="$1"
shift

case "${COMMAND}" in
    env_setup|format|lint|test_all|test_unit|test_integration|test_cov|test_no_warnings|test_strict_warnings|test_examples|perf_bench|perf_profile|audit_deps|run_hooks|build_pkg|release|clean|fuzz_all)
        "${COMMAND}" "$@"
        ;;
    help)
        help
        ;;
    *)
        error "Unknown command: ${COMMAND}"
        help
        exit 1
        ;;
esac
