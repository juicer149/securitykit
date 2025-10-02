import itertools
import time

from securitykit.bench.config import BenchmarkConfig
from securitykit.bench.runner import BenchmarkRunner
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm


def test_benchmark_runner_run(monkeypatch):
    Policy = get_policy_class("argon2")
    original_schema = Policy.BENCH_SCHEMA
    Policy.BENCH_SCHEMA = {
        "time_cost": [2, 3],
        "memory_cost": [65536],  # single-value dimension (nu robust)
    }

    def fast_hash(self, password: str):
        return "$h"

    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    seq = itertools.count()
    monkeypatch.setattr(time, "perf_counter", lambda: next(seq) * 0.0005)

    cfg = BenchmarkConfig(variant="argon2", target_ms=1, tolerance=0.5, rounds=2)
    runner = BenchmarkRunner(cfg)
    out = runner.run()

    assert "best" in out and "best_result" in out
    assert out["best"]["HASH_VARIANT"] == "argon2"
    assert out["best_result"].median >= 0
    assert len(out["schema_keys"]) == len(Policy.BENCH_SCHEMA)

    Policy.BENCH_SCHEMA = original_schema
