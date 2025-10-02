import time
import itertools
from securitykit.bench.engine import BenchmarkEngine, BenchmarkResult
from securitykit.hashing.policy_registry import get_policy_class


def test_benchmark_engine_run(monkeypatch):
    variant = "argon2"
    Policy = get_policy_class(variant)
    policy = Policy()

    # Patcha Algorithm.hash för snabbhet
    from securitykit.hashing.algorithm import Algorithm

    def fast_hash(self, password: str):
        return "x"  # no-op

    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    # Kontrollera att perf_counter ger deterministiska växande tider
    seq = itertools.count()
    monkeypatch.setattr(time, "perf_counter", lambda: next(seq) * 0.001)

    engine = BenchmarkEngine(variant=variant, repeats=3)
    result = engine.run(policy, target_ms=50)
    assert isinstance(result, BenchmarkResult)
    assert result.median >= 0  # liten men > 0
    assert result.target_ms == 50
    assert result.delta != 0  # med stor sannolikhet ej exakt 0
