# securitykit/bench/engine.py
import time
import statistics
from typing import Any, Sequence

from securitykit.core.algorithm import Algorithm


class BenchmarkResult:
    def __init__(self, policy: Any, times: Sequence[float], target_ms: int):
        self.policy = policy
        self.times = list(times)
        self.median = statistics.median(times)
        self.min = min(times)
        self.max = max(times)
        self.stddev = statistics.pstdev(times) if len(times) > 1 else 0.0
        self.delta = ((self.median - target_ms) / target_ms) * 100

    def __repr__(self):
        return f"<BenchmarkResult {self.policy} median={self.median:.2f}ms Δ={self.delta:+.1f}%>"


class BenchmarkEngine:
    """Run timing benchmarks for a given algorithm and policy."""

    def __init__(self, variant: str, repeats: int = 5):
        self.variant = variant
        self.repeats = repeats

    def _time_once(self, policy) -> float:
        algo = Algorithm(self.variant, policy)
        start = time.perf_counter()
        algo.hash("benchmark-password")
        return (time.perf_counter() - start) * 1000

    def run(self, policy, target_ms: int) -> BenchmarkResult:
        # Warmup (discard first run)
        self._time_once(policy)
        times = [self._time_once(policy) for _ in range(self.repeats)]
        return BenchmarkResult(policy, times, target_ms)
