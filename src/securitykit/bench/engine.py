# securitykit/bench/engine.py
import time
import statistics
from typing import Any
from dataclasses import dataclass, field

from securitykit.hashing.algorithm import Algorithm


@dataclass(frozen=True)
class BenchmarkResult:
    """Immutable container for benchmark results of one policy config."""

    policy: Any
    times: list[float]
    target_ms: int

    median: float = field(init=False)
    min: float = field(init=False)
    max: float = field(init=False)
    stddev: float = field(init=False)
    delta: float = field(init=False)

    def __post_init__(self):
        object.__setattr__(self, "median", statistics.median(self.times))
        object.__setattr__(self, "min", min(self.times))
        object.__setattr__(self, "max", max(self.times))
        object.__setattr__(self, "stddev", statistics.pstdev(self.times) if len(self.times) > 1 else 0.0)
        object.__setattr__(
            self,
            "delta",
            ((self.median - self.target_ms) / self.target_ms) * 100 if self.target_ms else 0.0,
        )

    def __repr__(self) -> str:
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
