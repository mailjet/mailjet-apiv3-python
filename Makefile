.PHONY: all clean clean-env clean-test clean-pyc clean-build clean-other help dev test test-debug test-cov pre-commit lint format format-docs analyze docs
.DEFAULT_GOAL := help

# The `.ONESHELL` and setting `SHELL` allows us to run commands that require
# `conda activate`
.ONESHELL:
SHELL := /bin/bash
# For GNU Make v4 and above, you must include the `-c` in order for `make` to find symbols from `PATH`
.SHELLFLAGS := -c -o pipefail -o errexit
CONDA_ACTIVATE = source $$(conda info --base)/etc/profile.d/conda.sh ; conda activate ; conda activate
# Ensure that we are using the python interpreter provided by the conda environment.
PYTHON3 := $(shell if [ -n "$${CONDA_PREFIX:-}" ] && [ -x "$${CONDA_PREFIX}/bin/python3" ]; then echo "$${CONDA_PREFIX}/bin/python3"; else command -v python3 2>/dev/null || command -v python 2>/dev/null; fi)

CONDA_ENV_NAME ?= mailjet-dev
SRC_DIR = mailjet_rest
TEST_DIR = tests
SCRIPTS_DIR = scripts

define BROWSER_PYSCRIPT
import os, webbrowser, sys

from urllib.request import pathname2url

webbrowser.open("file://" + pathname2url(os.path.abspath(sys.argv[1])))
endef
export BROWSER_PYSCRIPT

define PRINT_HELP_PYSCRIPT
import re, sys

for line in sys.stdin:
	match = re.match(r'^([a-zA-Z_-]+):.*?## (.*)$$', line)
	if match:
		target, help = match.groups()
		print("%-20s %s" % (target, help))
endef
export PRINT_HELP_PYSCRIPT

BROWSER := python -c "$$BROWSER_PYSCRIPT"

all:
	echo "All is a placeholder"

clean: clean-cov clean-build clean-pyc clean-test clean-temp clean-other ## remove all build, test, coverage and Python artifacts

clean-cov:
	rm -rf .coverage
	rm -rf htmlcov
	rm -rf reports/{*.html,*.png,*.js,*.css,*.json}
	rm -rf pytest.xml
	rm -rf pytest-coverage.txt

clean-build: ## remove build artifacts
	rm -fr build/
	rm -fr dist/
	rm -fr .eggs/
	find . -name '*.egg-info' -exec rm -fr {} +
	find . -name '*.egg' -exec rm -f {} +

clean-env:					## remove conda environment
	conda remove -y -n $(CONDA_ENV_NAME) --all ; conda info

clean-pyc: ## remove Python file artifacts
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -fr {} +

clean-test: ## remove test and coverage artifacts
	rm -fr .tox/
	rm -f .coverage
	rm -fr htmlcov/
	rm -fr .pytest_cache

clean-temp: ## remove temp artifacts
	rm -fr temp/tmp.txt
	rm -fr tmp.txt

clean-other:
	rm -fr *.prof
	rm -fr profile.html profile.json
	rm -fr wget-log
	rm -fr logs/*.log

help:
	$(PYTHON3) -c "$$PRINT_HELP_PYSCRIPT" < $(MAKEFILE_LIST)

environment:    ## handles environment creation
	conda env create -f environment.yaml --name $(CONDA_ENV_NAME) --yes
	conda run --name $(CONDA_ENV_NAME) pip install .

environment-dev:       ## Handles environment creation
	conda env create -n $(CONDA_ENV_NAME)-dev -y --file environment-dev.yaml
	conda run --name $(CONDA_ENV_NAME)-dev pip install -e .

install: clean	## install the package to the active Python's site-packages
	pip install .

release: dist ## package and upload a release
	twine upload dist/*

dist: clean ## builds source and wheel package
	python -m build
	ls -l dist

dev: clean		## install the package's development version to a fresh environment
	conda env create -f environment.yaml --name $(CONDA_ENV_NAME) --yes
	conda run --name $(CONDA_ENV_NAME) pip install -e .

dev-full: clean		## install the package's development version to a fresh environment
	conda env create -f environment-dev.yaml --name $(CONDA_ENV_NAME)-dev --yes
	conda run --name $(CONDA_ENV_NAME)-dev pip install -e .
	$(CONDA_ACTIVATE) $(CONDA_ENV_NAME)-dev && pre-commit install

pre-commit:     ## runs pre-commit against files. NOTE: older files are disabled in the pre-commit config.
	pre-commit run --all-files

test:			## runs all test cases
	$(PYTHON3) -m pytest -n auto --capture=no $(TEST_DIR)

test-unit:		## runs pure offline unit tests
	$(PYTHON3) -m pytest -n auto --capture=no $(TEST_DIR)/unit

test-integration:	## runs live network integration tests
	$(PYTHON3) -m pytest -n auto --capture=no $(TEST_DIR)/integration

test-debug:		## runs test cases with debugging info enabled
	$(PYTHON3) -m pytest -n auto -vv --capture=no $(TEST_DIR)

test-cov:		## checks test coverage requirements
	$(PYTHON3) -m pytest -n auto --cov-config=.coveragerc --cov=$(SRC_DIR) \
		$(TEST_DIR) --cov-fail-under=80 --cov-report term-missing

tests-cov-fail:
	@pytest --cov=$(SRC_DIR) --cov-report term-missing --cov-report=html --cov-fail-under=80

coverage: ## check code coverage quickly with the default Python
	coverage run --source $(SRC_DIR) -m pytest
	coverage report -m
	coverage html
	$(BROWSER) htmlcov/index.html

lint:			## runs ruff, mypy --strict, pyright, slotscheck, and bandit
	$(PYTHON3) -m ruff check .
	$(PYTHON3) -m ruff format --check .
	$(PYTHON3) -m mypy --strict $(SRC_DIR)
	pyright $(SRC_DIR)
	slotscheck -m $(SRC_DIR)
	bandit -c pyproject.toml -r $(SRC_DIR)

format:			## formats code with ruff
	$(PYTHON3) -m ruff format .
	$(PYTHON3) -m ruff check --fix .

format-docs:	## runs the docstring auto-formatter. Note this requires manually installing `docconvert` with `pip`
	docconvert --in-place --config .docconvert.json $(SRC_DIR)

analyze:		## runs static analyzers on the project
	$(PYTHON3) -m mypy --strict $(SRC_DIR)
	pyright $(SRC_DIR)
	slotscheck -m $(SRC_DIR)

lint-mypy-report:
	@mypy $(SRC_DIR) --html-report ./mypy_html
