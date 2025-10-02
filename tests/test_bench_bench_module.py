import itertools
import time
import pytest

from securitykit.bench.bench import run_benchmark, _measure
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing.policy_registry import register_policy


def test_run_benchmark_minimal(monkeypatch):
    Policy = get_policy_class("argon2")
    original_schema = Policy.BENCH_SCHEMA
    Policy.BENCH_SCHEMA = {
        "time_cost": [2, 3],
        "memory_cost": [65536],   # single-value dimension (safe efter patch)
        "parallelism": [1],       # single-value dimension (safe efter patch)
    }

    def fast_hash(self, password: str):
        return "h"

    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    seq = itertools.count()
    monkeypatch.setattr(time, "perf_counter", lambda: next(seq) * 0.001)

    result = run_benchmark("argon2", target_ms=1, tolerance=0.5, rounds=2)
    assert "best" in result
    assert result["best"]["HASH_VARIANT"] == "argon2"
    assert len(result["schema_keys"]) == 3

    Policy.BENCH_SCHEMA = original_schema


def test_run_benchmark_no_schema_raises(monkeypatch):
    @register_policy("emptybench")
    class EmptyBenchPolicy:
        BENCH_SCHEMA = {}

    with pytest.raises(RuntimeError):
        run_benchmark("emptybench")


def test__measure_function(monkeypatch):
    # Använd räkneverk i stället för begränsad lista (undviker StopIteration)
    import time as tmod
    seq = itertools.count()
    monkeypatch.setattr(tmod, "perf_counter", lambda: next(seq) * 0.001)

    from securitykit.hashing.policy_registry import get_policy_class
    from securitykit.hashing.algorithm import Algorithm

    Policy = get_policy_class("argon2")
    policy = Policy()
    algo = Algorithm("argon2", policy)

    def fast_hash(self, password: str):
        return "x"

    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    avg = _measure(policy, algo, rounds=5)
    # Varje mätning använder två perf_counter-anrop; med 0.001 ms mellanrum
    assert avg >= 0.0
    # Grovt rimligt spann
    assert avg < 10.0
