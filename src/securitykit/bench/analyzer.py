from __future__ import annotations

from typing import Sequence, Any, Callable, Iterable, Optional

from securitykit.hashing.interfaces import BenchValue
from .engine import BenchmarkResult


def _is_number(x: Any) -> bool:
    return isinstance(x, (int, float))


class ResultAnalyzer:
    """
    Analyze benchmark result sets.

    The design allows future extensibility:
      - pluggable balance strategies
      - weighting per dimension
      - filtering of specific dimensions
    """

    def __init__(self, schema: dict[str, list[BenchValue]]):
        self.schema = schema
        # In the future, this can be replaced with another strategy.
        self._balance_strategy: Callable[[BenchmarkResult], float] = self._default_balance_score

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def filter_near(
        self,
        results: Sequence[BenchmarkResult],
        target_ms: int,
        tolerance: float,
    ) -> list[BenchmarkResult]:
        lower, upper = target_ms * (1 - tolerance), target_ms * (1 + tolerance)
        return [r for r in results if lower <= r.median <= upper]

    def closest(self, results: Sequence[BenchmarkResult], target_ms: int) -> BenchmarkResult:
        return min(results, key=lambda r: abs(r.median - target_ms))

    def balanced(self, results: Sequence[BenchmarkResult]) -> BenchmarkResult:
        """
        Select configuration with most even parameter distribution.

        Delegates scoring to self._balance_strategy (default = variance of
        normalized dimension positions).
        """
        if not self.schema:
            return results[0]
        return min(results, key=self._balance_strategy)

    # ------------------------------------------------------------------
    # Strategy (default balance score)
    # ------------------------------------------------------------------

    def _default_balance_score(self, result: BenchmarkResult) -> float:
        """
        Compute a variance-based balance score for a single result.
        Lower = more evenly distributed.

        Pipeline:
          1. Iterate numeric dimensions
          2. Compute normalized position per dimension
          3. Neutral score (0.5) for single-value numeric dimensions
          4. Drop entirely non-numeric dimensions
          5. Aggregate via population variance
        """
        positions: list[float] = []
        for key, numeric_values in self._iter_numeric_dimensions():
            pos = self._compute_dimension_position(result, key, numeric_values)
            if pos is not None:
                positions.append(pos)

        if not positions:
            return 0.0
        return self._aggregate_variance(positions)

    # ------------------------------------------------------------------
    # Dimension iteration
    # ------------------------------------------------------------------

    def _iter_numeric_dimensions(self) -> Iterable[tuple[str, list[float]]]:
        """
        Yield (dimension_key, numeric_values) for each schema dimension
        that has at least one numeric value.
        """
        for key, values in self.schema.items():
            if not values:
                continue
            numeric_values = [float(v) for v in values if _is_number(v)]
            if not numeric_values:
                # Entirely non-numeric dimension → skip
                continue
            yield key, numeric_values

    # ------------------------------------------------------------------
    # Single dimension helpers
    # ------------------------------------------------------------------

    def _compute_dimension_position(
        self,
        result: BenchmarkResult,
        dim_key: str,
        numeric_values: list[float],
    ) -> Optional[float]:
        """
        Return normalized position for a policy's value in one dimension:

        - 0.5 if single-value dimension
        - None if the policy attribute is missing or non-numeric
        - clamped [0,1] if value falls slightly outside range (defensivt)
        """
        raw_val = getattr(result.policy, dim_key, None)
        if not _is_number(raw_val):
            return None

        val = float(raw_val)
        min_v = min(numeric_values)
        max_v = max(numeric_values)

        if max_v == min_v:
            return 0.5  # neutral

        norm = (val - min_v) / (max_v - min_v)
        if norm < 0:
            norm = 0.0
        elif norm > 1:
            norm = 1.0
        return norm

    # ------------------------------------------------------------------
    # Aggregation
    # ------------------------------------------------------------------

    @staticmethod
    def _aggregate_variance(values: list[float]) -> float:
        """
        Population variance (sum((x - mean)^2)) — no division needed for relative ordering;
        but if you want true variance you can divide by len(values).
        Keeping it as raw sum for speed & same ordering.
        """
        mean_val = sum(values) / len(values)
        return sum((v - mean_val) ** 2 for v in values)

    # ------------------------------------------------------------------
    # (Optional future extension points)
    # ------------------------------------------------------------------

    def set_balance_strategy(self, fn: Callable[[BenchmarkResult], float]) -> None:
        """
        Allow external injection of a custom scoring strategy.
        Strategy function should return a float (lower = better).
        """
        self._balance_strategy = fn
