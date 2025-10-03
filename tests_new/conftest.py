"""
Test configuration for the tests_new suite.

Responsibilities:
  - Dynamically parametrize algorithm and policy names
  - Ensure registries are loaded before parametrization
  - Isolate environment variables per test (automatic snapshot/restore)
  - Provide a fixture to restore registries after tests that mutate them
  - Provide common helpers (temp cwd, log capture)
  - Prevent accidental execution of real (slow) benchmarking runs in unit tests
"""
from __future__ import annotations
import io
import os
import logging
from pathlib import Path
import pytest

from securitykit.hashing.registry import load_all
from securitykit.hashing import algorithm_registry, policy_registry


# --- Dynamic parametrization -------------------------------------------------
def pytest_generate_tests(metafunc):
    """
    Pytest hook executed for every collected test function.

    Steps:
      1. Invoke load_all() (idempotent: first call discovers, subsequent calls no-op).
      2. If a fixture named 'algorithm_name' or 'policy_name' is requested, parametrize
         the test over all currently registered variants.
    """
    need_algo = "algorithm_name" in metafunc.fixturenames
    need_policy = "policy_name" in metafunc.fixturenames
    if not (need_algo or need_policy):
        return

    load_all()

    if need_algo:
        algos = algorithm_registry.list_algorithms()
        if not algos:
            pytest.skip("No algorithms registered.")
        metafunc.parametrize("algorithm_name", algos)

    if need_policy:
        policies = policy_registry.list_policies()
        if not policies:
            pytest.skip("No policies registered.")
        metafunc.parametrize("policy_name", policies)


# --- Registry reset (for tests that register temporary classes) --------------
@pytest.fixture
def registry_reset():
    """
    Use in tests that register temporary algorithms/policies to ensure isolation.

    Restores the algorithm and policy registries to their original snapshot after
    the test finishes.

    Silent best-effort rollback (exceptions during restore are ignored).
    """
    yield
    try:
        from securitykit.hashing.algorithm_registry import restore_from_snapshots
        from securitykit.hashing.policy_registry import restore_from_snapshots as restore_policies
        restore_from_snapshots()
        restore_policies()
    except Exception:
        # Deliberately ignore to avoid noisy teardown logs
        pass


# --- Environment isolation ---------------------------------------------------
@pytest.fixture(autouse=True)
def restore_env_each_test():
    """
    Automatically snapshot os.environ before each test and restore it afterwards.

    Ensures tests cannot leak environment variable modifications into subsequent
    tests (critical for config / pepper / benchmark related paths).
    """
    snapshot = os.environ.copy()
    try:
        yield
    finally:
        os.environ.clear()
        os.environ.update(snapshot)


# --- Common helpers: temp cwd & log capture ---------------------------------
@pytest.fixture
def chdir_tmp(tmp_path, monkeypatch):
    """
    Run test inside a temp directory so files like .env.local are isolated.
    """
    old = Path.cwd()
    monkeypatch.chdir(tmp_path)
    try:
        yield tmp_path
    finally:
        monkeypatch.chdir(old)


@pytest.fixture
def capture_logs():
    """
    Capture 'securitykit' logger output at DEBUG+ for assertions.
    """
    logger = logging.getLogger("securitykit")
    buffer = io.StringIO()
    handler = logging.StreamHandler(buffer)
    old_level = logger.level
    logger.setLevel(logging.DEBUG)
    logger.addHandler(handler)
    try:
        yield buffer
    finally:
        logger.removeHandler(handler)
        logger.setLevel(old_level)


# --- Prevent real benchmarking in unit tests ---------------------------------
@pytest.fixture(autouse=True)
def forbid_real_benchmark(monkeypatch):
    """
    Block accidental invocation of the real BenchmarkRunner.run (which would
    perform potentially slow timing loops). Tests that intentionally exercise
    bootstrap/benchmark flows should monkeypatch this method again (e.g. to a stub)
    inside the test or via a dedicated fixture.

    Fails fast with an AssertionError if the real runner is invoked.
    """
    import securitykit.bench.runner as runner_mod
    def blocked(self):  # noqa: D401 - short intentional
        raise AssertionError("Real BenchmarkRunner.run invoked in tests.")
    monkeypatch.setattr(runner_mod.BenchmarkRunner, "run", blocked)
