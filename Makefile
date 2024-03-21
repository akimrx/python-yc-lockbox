.PHONY: sec lint lint-apply test tests test-no-cov init pre-commit build install clean release
.DEFAULT_GOAL := help

help:
	@echo "🪄  PREPARE ENVIRONMENT"
	@echo "---------------------------------------------------------------------"
	@echo "  init                Install all python requirements"
	@echo "  pre-commit          Install pre-commit hooks"
	@echo ""
	@echo "⚙️  DEVELOPMENT"
	@echo "---------------------------------------------------------------------"
	@echo "  test                Run all tests (pytest)"
	@echo "  test-no-cov         Run all tests (pytest) without coverage report"
	@echo "  lint                Check python syntax & style by black"
	@echo "  lint-apply          Apply black linter (autoformat)"
	@echo "  sec                 Security linter (bandit)"
	@echo ""
	@echo "📦  PACKAGE OPERATIONS"
	@echo "---------------------------------------------------------------------"
	@echo "  build               Build whl package"
	@echo "  install             Install package to python lib"
	@echo "  clean               Clean install artifacts"
	@echo "  release             Build & release new package version to PYPI"

sec:
	@bandit -r yc_lockbox

lint:
	@black yc_lockbox tests --color --diff --check --extend-exclude "/.*(\.yml|\.yaml)/"

lint-apply:
	@black yc_lockbox tests --extend-exclude "/.*(\.yml|\.yaml)/"

test:
	@pytest -vv --cov=yc_lockbox --cov-report term --cov-report xml:coverage.xml

tests: test

test-no-cov:
	@pytest -vv --log-cli-level=INFO

pre-commit:
	@pre-commit run --all-files

init:
	@pip install -r requirements.txt
	@pip install -r requirements.aio.txt
	@pip install -r requirements.dev.txt

clean: clean-build clean-pyc

clean-build:
	rm -rf build/
	rm -rf dist/
	rm -rf .eggs/
	find . -name '*.egg-info' -exec rm -rf {} +
	find . -name '*.egg' -exec rm -rf {} +
	find . -name '.DS_Store' -exec rm -f {} +

clean-pyc:
	find . -name '*.pyc' -exec rm -f {} +
	find . -name '*.pyo' -exec rm -f {} +
	find . -name '*~' -exec rm -f {} +
	find . -name '__pycache__' -exec rm -rf {} +

build:
	@python3 setup.py sdist bdist_wheel

install: clean
	@python3 setup.py install

release: build
	@make build
	@echo "not implemented"