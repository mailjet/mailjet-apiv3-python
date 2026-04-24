#!/usr/bin/env bash

# Exit immediately if a command exits with a non-zero status
set -e

# ==============================================================================
# GLOBAL VARIABLES & SETUP
# ==============================================================================
SRC_DIR="mailjet_rest"
TEST_DIR="tests"
CONDA_ENV_NAME="mailjet-dev"

# Color formatting for terminal output
CYAN='\033[1;36m'
GREEN='\033[1;32m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
NC='\033[0m' # No Color

info() { echo -e "${CYAN}=> $1${NC}"; }
success() { echo -e "${GREEN}=> $1${NC}"; }
warn() { echo -e "${YELLOW}=> WARNING: $1${NC}"; }
error() { echo -e "${RED}=> ERROR: $1${NC}"; }

# ==============================================================================
# ENVIRONMENT & SETUP
# ==============================================================================
env_setup() {
    # Example: ./manage.sh env_setup
    info "Creating and updating conda environment '${CONDA_ENV_NAME}'..."
    conda env create -n "${CONDA_ENV_NAME}" -y --file environment-dev.yaml || conda env update -n "${CONDA_ENV_NAME}" --file environment-dev.yaml
    info "Installing package in editable mode..."
    conda run --name "${CONDA_ENV_NAME}" pip install -e .
    info "Installing pre-commit hooks..."
    conda run --name "${CONDA_ENV_NAME}" pre-commit install
    success "Environment ready! Don't forget to run: conda activate ${CONDA_ENV_NAME}"
}

# ==============================================================================
# FORMATTING & LINTING (Modernized 2026 Stack)
# ==============================================================================
format() {
    # Example: ./manage.sh format
    info "Formatting code with Ruff (replaces Black/Isort)..."
    ruff format "${SRC_DIR}" "${TEST_DIR}" scripts/
    info "Applying safe auto-fixes..."
    ruff check --fix "${SRC_DIR}" "${TEST_DIR}" scripts/
    success "Code formatted successfully."
}

lint() {
    # Example: ./manage.sh lint
    info "Running Ruff linter (replaces Flake8/Pylint)..."
    ruff check "${SRC_DIR}" "${TEST_DIR}"
    info "Running MyPy strict type checking..."
    mypy "${SRC_DIR}" "${TEST_DIR}"
    success "Linting passed!"
}

# ==============================================================================
# TESTING SCENARIOS
# ==============================================================================
# Note: "$@" allows you to pass ANY extra pytest flags (like -s, -vvv, or -k "test_name")

test_all() {
    # Example: ./manage.sh test_all
    # Example with flags: ./manage.sh test_all -vvv -s
    info "Running ALL tests (Unit + Integration)..."
    pytest -n auto "${TEST_DIR}" "$@"
}

test_unit() {
    # Example: ./manage.sh test_unit
    # Example specific test: ./manage.sh test_unit tests/unit/test_client.py::test_get_version
    # Example specific class: ./manage.sh test_unit -k "TestClientAuth"
    info "Running UNIT tests..."
    pytest "${TEST_DIR}/unit" "$@"
}

test_integration() {
    # Example: ./manage.sh test_integration
    info "Running INTEGRATION tests..."
    pytest "${TEST_DIR}/integration" "$@"
}

test_cov() {
    # Example: ./manage.sh test_cov
    info "Running tests with Coverage requirements (Fail under 80%)..."
    pytest -n auto --cov="${SRC_DIR}" "${TEST_DIR}" --cov-fail-under=80 --cov-report=term-missing --cov-report=html
    success "Coverage report generated in htmlcov/index.html"
}

test_no_warnings() {
    # Example: ./manage.sh test_no_warnings
    # Example for specific group: ./manage.sh test_no_warnings tests/unit/
    info "Running tests and SUPPRESSING all DeprecationWarnings..."
    pytest -W "ignore::DeprecationWarning" "$@"
}

test_strict_warnings() {
    # Example: ./manage.sh test_strict_warnings
    info "Running tests and treating DeprecationWarnings as ERRORS..."
    pytest -W "error::DeprecationWarning" "$@"
}

# ==============================================================================
# PERFORMANCE & BENCHMARKING
# ==============================================================================
perf_bench() {
    # Example: ./manage.sh perf_bench
    # Example compare: ./manage.sh perf_bench --benchmark-compare
    info "Running pytest-benchmark performance tests..."
    pytest "${TEST_DIR}/test_perf.py" "$@"
}

perf_profile() {
    # Example: ./manage.sh perf_profile
    info "Running cold-boot profiler (cProfile)..."
    python "${TEST_DIR}/test_boot.py"
}

# ==============================================================================
# SECURITY AUDITS & PRE-COMMIT
# ==============================================================================
audit_deps() {
    # Example: ./manage.sh audit_deps
    info "Running pip-audit for known vulnerabilities..."
    pip-audit || warn "pip-audit found issues."

    if command -v osv-scanner &> /dev/null; then
        info "Running Google OSV-Scanner..."
        osv-scanner -r .
    else
        warn "osv-scanner not found. Skipping."
    fi
}

run_hooks() {
    # Example: ./manage.sh run_hooks
    info "Running all pre-commit hooks (including slotscheck, gitleaks, etc.)..."
    pre-commit run --all-files
}

# ==============================================================================
# BUILD & RELEASE
# ==============================================================================
build_pkg() {
    # Example: ./manage.sh build_pkg
    clean
    info "Building source and wheel distribution..."
    python -m build
    ls -l dist
    success "Build complete."
}

release() {
    # Example: ./manage.sh release
    build_pkg
    info "Uploading to PyPI via Twine..."
    twine upload dist/*
}

# ==============================================================================
# CLEANUP
# ==============================================================================
clean() {
    # Example: ./manage.sh clean
    info "Cleaning up workspace (caches, builds, coverage)..."

    # Python caches
    find . -type d -name '__pycache__' -exec rm -rf {} +
    find . -type f -name '*.py[co]' -exec rm -f {} +
    find . -type f -name '*~' -exec rm -f {} +

    # Test & Coverage artifacts
    rm -rf .pytest_cache/ .mypy_cache/ .ruff_cache/ .tox/
    rm -rf .coverage htmlcov/ coverage.xml reports/

    # Build artifacts
    rm -rf build/ dist/ .eggs/
    find . -type d -name '*.egg-info' -exec rm -rf {} +
    find . -type f -name '*.egg' -exec rm -f {} +

    # Temp logs and profilers
    rm -f *.prof profile.html profile.json tmp.txt wget-log

    success "Workspace cleaned!"
}

# ==============================================================================
# MAIN ROUTER & HELP
# ==============================================================================
help() {
    echo -e "${CYAN}Mailjet SDK Management Script${NC}"
    echo "Usage: ./manage.sh <command> [extra_arguments...]"
    echo ""
    echo -e "${YELLOW}Development & Code Quality:${NC}"
    echo "  env_setup         - Create/update conda dev env and install pre-commit"
    echo "  format            - Format code (Ruff)"
    echo "  lint              - Run linters and type checkers (Ruff, MyPy)"
    echo "  run_hooks         - Run all pre-commit hooks manually (slotscheck, etc.)"
    echo ""
    echo -e "${YELLOW}Testing (Any pytest flags like '-s', '-vvv', '-k' can be added at the end):${NC}"
    echo "  test_all          - Run all tests"
    echo "  test_unit         - Run only unit tests"
    echo "  test_integration  - Run only integration tests"
    echo "  test_cov          - Run tests with HTML coverage report"
    echo "  test_no_warnings  - Run tests and hide all DeprecationWarnings"
    echo "  test_strict_warnings - Run tests and fail on any DeprecationWarning"
    echo ""
    echo -e "${YELLOW}Performance & Security:${NC}"
    echo "  perf_bench        - Run pytest-benchmark suite"
    echo "  perf_profile      - Run cProfile on cold boot"
    echo "  audit_deps        - Run pip-audit and osv-scanner"
    echo ""
    echo -e "${YELLOW}Build & Maintenance:${NC}"
    echo "  clean             - Remove all build, test, and cache artifacts"
    echo "  build_pkg         - Build source and wheel package"
    echo "  release           - Build and upload release to PyPI"
    echo "  help              - Show this menu"
    echo ""
    echo -e "${GREEN}Examples:${NC}"
    echo "  ./manage.sh test_unit -vvv -s"
    echo "  ./manage.sh test_unit -k \"test_pep578_audit_hooks\""
    echo "  ./manage.sh test_no_warnings tests/unit/test_client.py"
}

# Check if at least one argument is provided
if [ $# -eq 0 ]; then
    help
    exit 1
fi

COMMAND=$1
shift # Remove the command from the arguments list, leaving only extra flags

case "$COMMAND" in
    env_setup|format|lint|test_all|test_unit|test_integration|test_cov|test_no_warnings|test_strict_warnings|perf_bench|perf_profile|audit_deps|run_hooks|build_pkg|release|clean|help)
        "$COMMAND" "$@" # Execute the function with any remaining arguments
        ;;
    *)
        error "Unknown command: $COMMAND"
        help
        exit 1
        ;;
esac
