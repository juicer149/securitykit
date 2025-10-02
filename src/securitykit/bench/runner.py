# securitykit/bench/runner.py
from typing import Any
from tqdm import tqdm
import logging

from securitykit.hashing.interfaces import BenchValue
from securitykit.bench.engine import BenchmarkEngine, BenchmarkResult
from securitykit.bench.analyzer import ResultAnalyzer
from securitykit.bench.config import BenchmarkConfig
from securitykit.logging_config import logger


class BenchmarkRunner:
    def __init__(self, config: BenchmarkConfig):
        self.config = config
        self.analyzer = ResultAnalyzer(config.schema)
        self.engine = BenchmarkEngine(config.variant, repeats=config.rounds)

    def run(self) -> dict[str, Any]:
        results = self._collect_results()
        best_result, near = self._analyze_results(results)
        env_config = self._build_env_config(best_result)

        return {
            "best": env_config,
            "best_result": best_result,
            "near": near,
            "schema_keys": list(self.config.schema.keys()),
        }

    def _collect_results(self) -> list[BenchmarkResult]:
        schema = self.config.schema
        results: list[BenchmarkResult] = []

        total = 1
        for values in schema.values():
            total *= len(values)

        kit_logger = logging.getLogger("securitykit")
        prev_level = kit_logger.level
        kit_logger.setLevel(logging.ERROR)

        try:
            with tqdm(total=total, desc=f"Benchmarking {self.config.variant}") as bar:
                for combo in self._cartesian(schema):
                    policy = self.config.policy_cls(**combo)
                    result = self.engine.run(policy, self.config.target_ms)
                    results.append(result)
                    bar.update(1)
        finally:
            kit_logger.setLevel(prev_level)

        return results

    def _analyze_results(
        self, results: list[BenchmarkResult]
    ) -> tuple[BenchmarkResult, list[BenchmarkResult]]:
        near_all = self.analyzer.filter_near(results, self.config.target_ms, tolerance=self.config.tolerance)

        best_result = (
            self.analyzer.balanced(near_all)
            if near_all
            else self.analyzer.closest(results, self.config.target_ms)
        )
        near = [r for r in near_all if r is not best_result]

        best_combo = {k: getattr(best_result.policy, k) for k in self.config.schema.keys()}
        logger.info(
            "Best config for %s: %s → %.2f ms (target=%d ms)",
            self.config.variant,
            best_combo,
            best_result.median,
            self.config.target_ms,
        )

        return best_result, near

    def _build_env_config(self, best_result: BenchmarkResult) -> dict[str, str]:
        schema_keys = self.config.schema.keys()
        best_combo = {k: getattr(best_result.policy, k) for k in schema_keys}

        env_config: dict[str, str] = {"HASH_VARIANT": str(self.config.variant)}
        env_config.update(
            {f"{self.config.variant.upper()}_{k.upper()}": str(v) for k, v in best_combo.items()}
        )
        return env_config

    @staticmethod
    def _cartesian(schema: dict[str, list[BenchValue]]):
        if not schema:
            return
        keys = list(schema.keys())

        def helper(idx: int, current: dict[str, BenchValue]):
            if idx == len(keys):
                yield dict(current)
                return
            key = keys[idx]
            for value in schema[key]:
                current[key] = value
                yield from helper(idx + 1, current)

        yield from helper(0, {})
