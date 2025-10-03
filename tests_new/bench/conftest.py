"""
Shared bench test fixtures:
  - Ensure registries discovered for bench package
  - Default tiny Argon2 BENCH_SCHEMA (autouse)
  - Optional helpers to speed/determinize timing in engine/bench tests
  - Optional helper to reload runner module (to bypass root monkeypatch in specific tests)
"""
from __future__ import annotations
import time
import importlib
import pytest

from securitykit.hashing.registry import load_all
from securitykit.hashing.policies.argon2 import Argon2Policy


@pytest.fixture(scope="session", autouse=True)
def _bench_discovery():
    """Ensure algorithm/policy modules are registered once for bench tests."""
    load_all()


@pytest.fixture(autouse=True)
def tiny_argon2_schema(monkeypatch):
    """
    Keep Argon2 BENCH_SCHEMA small by default to keep any cartesian enumeration fast.
    Individual tests can override with their own monkeypatch if needed.
    """
    monkeypatch.setattr(
        Argon2Policy,
        "BENCH_SCHEMA",
        {
            "time_cost": [2],
            "memory_cost": [64 * 1024],
            "parallelism": [1],
        },
        raising=True,
    )


@pytest.fixture
def patch_algo_hash(monkeypatch):
    """
    Replace Algorithm.hash with a fast no-op for deterministic/quick engine timing tests.
    Opt-in: only used by tests that request it.
    """
    import securitykit.hashing.algorithm as algo_mod

    def fake_hash(self, password: str) -> str:
        return "HASHED-" + password

    monkeypatch.setattr(algo_mod.Algorithm, "hash", fake_hash)
    return fake_hash


@pytest.fixture
def patch_perf_counter(monkeypatch):
    """
    Make time.perf_counter deterministic by incrementing with a fixed delta.
    Opt-in: only used by tests that request it.
    """
    counter = {"v": 1000.0}

    def fake_counter():
        counter["v"] += 0.002  # 2 ms per call
        return counter["v"]

    monkeypatch.setattr(time, "perf_counter", fake_counter)
    return fake_counter


@pytest.fixture
def reload_runner_module():
    """
    Reload bench.runner to restore the original class methods for tests that need
    to re-monkeypatch inside that module's namespace (useful to bypass the root
    autouse 'forbid_real_benchmark' by reloading/resetting the module).
    """
    import securitykit.bench.runner as runner_mod
    return importlib.reload(runner_mod)
