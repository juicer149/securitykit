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
	@echo "  make install     Install project in editable mode"
	@echo "  make test        Run test suite with pytest"
	@echo "  make lint        Run ruff linter"
	@echo "  make format      Auto-format code with black"
	@echo "  make typecheck   Run mypy type checks"
	@echo "  make clean       Remove caches and build artifacts"

venv:
	python -m venv $(VENV)
	$(PIP) install --upgrade pip

install: venv
	$(PIP) install -e ".[dev]"

test:
	$(PYTEST) -v --cov=src --cov-report=term-missing

lint:
	$(VENV)/bin/ruff check src tests

format:
	$(VENV)/bin/black src tests

typecheck:
	$(VENV)/bin/mypy src

# Clean pyc/__pycache__
clean:
	find . -type f -name '*.pyc' -delete
	find . -type d -name '__pycache__' -exec rm -r {} +
