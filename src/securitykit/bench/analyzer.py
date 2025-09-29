# securitykit/bench/analyzer.py
from typing import Sequence

from .engine import BenchmarkResult


class ResultAnalyzer:
    def __init__(self, schema: dict[str, list]):
        self.schema = schema

    def filter_near(self, results: Sequence[BenchmarkResult], target_ms: int, tolerance: float) -> list[BenchmarkResult]:
        lower, upper = target_ms * (1 - tolerance), target_ms * (1 + tolerance)
        return [r for r in results if lower <= r.median <= upper]

    def closest(self, results: Sequence[BenchmarkResult], target_ms: int) -> BenchmarkResult:
        return min(results, key=lambda r: abs(r.median - target_ms))

    def balanced(self, results: Sequence[BenchmarkResult]) -> BenchmarkResult:
        def balance_score(result: BenchmarkResult) -> float:
            scores = []
            for k, values in self.schema.items():
                min_v, max_v = min(values), max(values)
                val = getattr(result.policy, k)
                scores.append((val - min_v) / (max_v - min_v))
            mean_val = sum(scores) / len(scores)
            return sum((s - mean_val) ** 2 for s in scores)

        return min(results, key=balance_score)
