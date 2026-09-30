# Virtual environment
VENV := .venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip
PYTEST := $(VENV)/bin/pytest

# Default target
.DEFAULT_GOAL := help

help:
	@echo "Available commands:"
	@echo "  make venv        Create virtual environment and install deps"
	@echo "  make install     Install project in editable mode (dev + bench extras)"
	@echo "  make install-core Install project in editable mode (core only)"
	@echo "  make test        Run test suite with pytest"
	@echo "  make lint        Run ruff linter"
	@echo "  make format      Auto-format code with black"
	@echo "  make typecheck   Run mypy type checks"
	@echo "  make bench       Run benchmark (pass args via ARGS='...')"
	@echo "  make clean       Remove caches and build artifacts"

venv:
	python3 -m venv $(VENV)
	$(PIP) install --upgrade pip setuptools wheel

install: venv
	$(PIP) install -e ".[dev,bench]"

# Optional: core-only install (no algorithm deps)
install-core: venv
	$(PIP) install -e .

test:
	$(PYTEST) -v --cov=src --cov-report=term-missing

lint:
	$(VENV)/bin/ruff check src tests_new

format:
	$(VENV)/bin/black src tests_new

typecheck:
	$(VENV)/bin/mypy src

bench:
	$(PYTHON) -m securitykit.bench.bench $(ARGS)

# Clean pyc/__pycache__
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -exec rm -r {} +
