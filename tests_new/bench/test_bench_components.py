import time
from dataclasses import dataclass
from typing import Any

import pytest

from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.bench.analyzer import ResultAnalyzer
from securitykit.bench.engine import BenchmarkResult, BenchmarkEngine
from securitykit.bench.bench import run_benchmark, _format_policy_line
from securitykit.bench.enumerator import PolicyEnumerator


# ---------------------------------------------------------------------------
# Analyzer tests
# ---------------------------------------------------------------------------

def test_analyzer_filter_near_and_closest():
    schema = {"time_cost": [2, 3, 4]}
    analyzer = ResultAnalyzer(schema)
    # Create three results around target=10 ms
    r_low = BenchmarkResult(policy=Argon2Policy(time_cost=2), times=[8.5], target_ms=10)
    r_mid = BenchmarkResult(policy=Argon2Policy(time_cost=3), times=[10.1], target_ms=10)
    r_high = BenchmarkResult(policy=Argon2Policy(time_cost=4), times=[12.8], target_ms=10)

    all_res = [r_low, r_mid, r_high]
    near = analyzer.filter_near(all_res, target_ms=10, tolerance=0.15)  # ±15% => [8.5, 11.5]
    assert r_low in near
    assert r_mid in near
    assert r_high not in near

    closest = analyzer.closest(all_res, target_ms=10)
    assert closest is r_mid


def test_analyzer_balanced_variance_and_custom_strategy():
    # Two numeric dimensions to exercise variance scoring
    schema = {"time_cost": [2, 4, 6], "parallelism": [1, 2, 3]}
    analyzer = ResultAnalyzer(schema)

    # r1 sits "centrally" (expect lower variance)
    r1 = BenchmarkResult(
        policy=Argon2Policy(time_cost=4, parallelism=2, memory_cost=65536),
        times=[50.0],
        target_ms=50,
    )
    # r2 at extremes (expect higher variance)
    r2 = BenchmarkResult(
        policy=Argon2Policy(time_cost=2, parallelism=3, memory_cost=65536),
        times=[49.0],
        target_ms=50,
    )

    best_balanced = analyzer.balanced([r1, r2])
    assert best_balanced is r1

    # Inject custom scoring to force picking r2
    analyzer.set_balance_strategy(lambda r: 0 if r is r2 else 1)
    forced = analyzer.balanced([r1, r2])
    assert forced is r2


def test_analyzer_empty_schema_returns_first():
    analyzer = ResultAnalyzer({})
    a = BenchmarkResult(policy=Argon2Policy(), times=[1.0], target_ms=1)
    b = BenchmarkResult(policy=Argon2Policy(time_cost=3), times=[2.0], target_ms=1)
    # With empty schema, balanced should just return first result
    assert analyzer.balanced([a, b]) is a


# ---------------------------------------------------------------------------
# Engine tests (use patch_algo_hash, patch_perf_counter from bench/conftest.py)
# ---------------------------------------------------------------------------

def test_engine_deterministic_timings(patch_algo_hash, patch_perf_counter):
    engine = BenchmarkEngine("argon2", repeats=3)
    policy = Argon2Policy(time_cost=2, memory_cost=65536, parallelism=1)
    result = engine.run(policy, target_ms=100)
    # With 3 timing samples, we have deterministic increasing fake times ~ 2ms each
    assert result.min <= result.median <= result.max
    assert result.delta != 0  # target_ms != median ⇒ delta computed
    assert result.stddev >= 0


# ---------------------------------------------------------------------------
# Enumerator tests
# ---------------------------------------------------------------------------

def test_policy_enumerator_cartesian():
    @dataclass(frozen=True)
    class TinyPolicy:
        a: int = 1
        b: int = 10

    schema = {"a": [1, 2], "b": [10, 20]}
    enum = PolicyEnumerator(TinyPolicy, schema)
    combos = list(enum.generate())
    assert len(combos) == 4
    observed = {(p.a, p.b) for p in combos}
    assert observed == {(1, 10), (1, 20), (2, 10), (2, 20)}


# ---------------------------------------------------------------------------
# run_benchmark (bench.bench) smoke test
# ---------------------------------------------------------------------------

def test_run_benchmark_smoke(monkeypatch, patch_algo_hash, patch_perf_counter):
    # Narrow Argon2 schema to a tiny space for speed
    monkeypatch.setattr(
        Argon2Policy,
        "BENCH_SCHEMA",
        {"time_cost": [2], "memory_cost": [65536], "parallelism": [1]},
    )
    data = run_benchmark("argon2", target_ms=10, tolerance=0.50, rounds=2)
    assert "best" in data and "best_result" in data
    best = data["best"]
    # Exported keys should include HASH_VARIANT + uppercase dimension keys
    assert best.get("HASH_VARIANT") == "argon2"
    assert any(k.startswith("ARGON2_TIME_COST") for k in best)
    # Formatting helper branch coverage
    line = _format_policy_line(
        data["best_result"].policy,
        schema_keys=data["schema_keys"],
        ms=data["best_result"].median,
        delta_pct=data["best_result"].delta,
    )
    assert "time_cost" in line


# ---------------------------------------------------------------------------
# Balanced variance edge cases
# ---------------------------------------------------------------------------

def test_analyzer_balance_single_value_dimension():
    # All dimensions single-valued → every position 0.5 → variance 0
    schema = {"time_cost": [3], "parallelism": [2]}
    analyzer = ResultAnalyzer(schema)
    r = BenchmarkResult(policy=Argon2Policy(time_cost=3, parallelism=2), times=[1.0], target_ms=1)
    assert analyzer.balanced([r]) is r
    # Internal score zero
    score = analyzer._default_balance_score(r)
    assert score == 0.0
