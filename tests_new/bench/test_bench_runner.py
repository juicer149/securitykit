import importlib
import logging
from typing import Any, List

import pytest

from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.hashing.registry import load_all


@pytest.fixture(scope="module", autouse=True)
def _ensure_discovery():
    load_all()


@pytest.fixture
def reload_runner_module():
    import securitykit.bench.runner as runner_mod
    runner_mod = importlib.reload(runner_mod)
    return runner_mod


@pytest.fixture
def shrink_schema(monkeypatch):
    monkeypatch.setattr(
        Argon2Policy,
        "BENCH_SCHEMA",
        {
            "time_cost": [2, 5],
            "parallelism": [1],
            "memory_cost": [64 * 1024],
        },
    )


@pytest.fixture
def patch_engine_times(reload_runner_module, monkeypatch):
    from securitykit.bench.engine import BenchmarkResult, BenchmarkEngine as RealEngine

    def fake_run(self, policy, target_ms: int):
        median = 100.0 if policy.time_cost == 2 else 160.0
        times = [median - 1.0, median, median + 1.0]
        return BenchmarkResult(policy=policy, times=times, target_ms=target_ms)

    monkeypatch.setattr(reload_runner_module, "BenchmarkEngine", RealEngine, raising=True)
    monkeypatch.setattr(RealEngine, "run", fake_run, raising=True)
    return fake_run


def test_runner_with_near_candidates(
    reload_runner_module,
    shrink_schema,
    patch_engine_times,
    caplog,
):
    """
    Both synthesized results fall within the tolerance window, so:
      - near_all contains BOTH results
      - balanced() chooses one as best (tie -> implementation order or other tie-break)
      - 'near' list contains exactly the other remaining result
    We assert structural correctness rather than which specific median is picked.
    """
    from securitykit.bench.config import BenchmarkConfig

    caplog.set_level(logging.INFO, logger="securitykit")

    cfg = BenchmarkConfig(
        variant="argon2",
        target_ms=120,   # Window [72,168] with tolerance 0.40 includes 100 & 160
        tolerance=0.40,
        rounds=2,
    )
    runner = reload_runner_module.BenchmarkRunner(cfg)
    data = runner.run()

    assert set(data.keys()) == {"best", "best_result", "near", "schema_keys"}

    env_cfg = data["best"]
    assert env_cfg["HASH_VARIANT"] == "argon2"
    assert any(k.startswith("ARGON2_TIME_COST") for k in env_cfg)

    best_result = data["best_result"]
    assert best_result.median in (100.0, 160.0)

    # After removal of best, exactly one remains in 'near'
    assert isinstance(data["near"], list)
    assert len(data["near"]) == 1
    remaining = data["near"][0]
    assert remaining.median in (100.0, 160.0) and remaining.median != best_result.median

    # Sanity: the remaining candidate is actually closer (or farther) than best depending
    # on which got picked—just assert they differ relative to target for coverage clarity.
    dist_best = abs(best_result.median - cfg.target_ms)
    dist_remaining = abs(remaining.median - cfg.target_ms)
    assert dist_best != dist_remaining

    # Log produced
    assert any("Best config for argon2" in rec.message for rec in caplog.records)


def test_runner_fallback_to_closest(
    reload_runner_module,
    shrink_schema,
    patch_engine_times,
):
    from securitykit.bench.config import BenchmarkConfig

    cfg = BenchmarkConfig(
        variant="argon2",
        target_ms=120,
        tolerance=0.05,  # Window [114,126] includes neither 100 nor 160
        rounds=2,
    )
    runner = reload_runner_module.BenchmarkRunner(cfg)
    data = runner.run()

    assert data["best_result"].median == 100.0  # closer to 120
    assert data["near"] == []


def test_runner_build_env_config_format(reload_runner_module, shrink_schema, patch_engine_times):
    from securitykit.bench.config import BenchmarkConfig
    from securitykit.bench.engine import BenchmarkResult

    cfg = BenchmarkConfig(
        variant="argon2",
        target_ms=200,
        tolerance=0.10,
        rounds=1,
    )
    runner = reload_runner_module.BenchmarkRunner(cfg)

    policy = cfg.policy_cls(time_cost=2, memory_cost=64 * 1024, parallelism=1)
    fake_result = BenchmarkResult(policy, times=[100.0, 101.0], target_ms=200)

    env_cfg = runner._build_env_config(fake_result)
    assert env_cfg["HASH_VARIANT"] == "argon2"
    assert "ARGON2_TIME_COST" in env_cfg
    assert "ARGON2_PARALLELISM" in env_cfg


def test_runner_cartesian_empty_schema(reload_runner_module):
    out = list(reload_runner_module.BenchmarkRunner._cartesian({}))
    assert out == []
