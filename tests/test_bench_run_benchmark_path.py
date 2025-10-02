import itertools
import time

from securitykit.bench import bench
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm


def test_run_benchmark_with_near_and_best(monkeypatch):
    # Gör schema litet men med två dimensioner så near_all inte blir tomt
    Policy = get_policy_class("argon2")
    original_schema = Policy.BENCH_SCHEMA
    Policy.BENCH_SCHEMA = {
        "time_cost": [2, 3],
        "memory_cost": [65536],
        "parallelism": [1],
    }

    # Snabb hash
    def fast_hash(self, password: str):
        return "x"
    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    # Deterministisk/perf-tidsmock
    seq = itertools.count()
    monkeypatch.setattr(time, "perf_counter", lambda: next(seq) * 0.0002)

    result = bench.run_benchmark("argon2", target_ms=1, tolerance=0.9, rounds=1)

    # best + near + schema_keys
    assert "best" in result and "near" in result and "schema_keys" in result
    assert result["best"]["HASH_VARIANT"] == "argon2"
    # near kan vara 0 eller >0 beroende på timing – men vi kontrollerar att koden kördes
    assert isinstance(result["near"], list)
    # env_config nycklar
    best_keys = result["best"].keys()
    assert any(k.startswith("ARGON2_TIME_COST") for k in best_keys)

    # Återställ schema
    Policy.BENCH_SCHEMA = original_schema


def test_export_env_function(tmp_path):
    cfg = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "2",
    }
    target = tmp_path / ".env.exported"
    bench.export_env(cfg, target)
    content = target.read_text().splitlines()
    assert "HASH_VARIANT=argon2" in content
    assert "ARGON2_TIME_COST=2" in content
