# src/securitykit/bench/bench.py
from __future__ import annotations

import time
import logging
import warnings
from pathlib import Path
from statistics import mean
from typing import Any, Iterable

import click
from tqdm import tqdm

from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm
from securitykit.logging_config import logger
from securitykit.bench.engine import BenchmarkResult
from securitykit.bench.analyzer import ResultAnalyzer
from securitykit.bench.config import (
    DEFAULT_TARGET_MS,
    DEFAULT_TOLERANCE,
    DEFAULT_ROUNDS,
)
from securitykit.config import DEFAULTS, ENV_VARS

# Silence the benign "found in sys.modules" RuntimeWarning when running as a module.
warnings.filterwarnings(
    "ignore",
    category=RuntimeWarning,
    message=r".*found in sys\.modules after import of package 'securitykit\.bench'.*",
)


def _measure(policy: Any, hasher: Algorithm, rounds: int = DEFAULT_ROUNDS) -> float:
    """Measure average hash time (ms) for a given policy."""
    timings = []
    for _ in range(rounds):
        start = time.perf_counter()
        hasher.hash("benchmark-password")
        end = time.perf_counter()
        timings.append((end - start) * 1000)
    return mean(timings)


def _cartesian(schema: dict[str, list[Any]]) -> Iterable[dict[str, Any]]:
    """Yield all combinations of schema parameters (preserving BENCH_SCHEMA key order)."""
    if not schema:
        return
    keys = list(schema.keys())

    def helper(idx: int, current: dict[str, Any]):
        if idx == len(keys):
            yield dict(current)
            return
        key = keys[idx]
        for value in schema[key]:
            current[key] = value
            yield from helper(idx + 1, current)

    yield from helper(0, {})


def _format_policy_line(
    policy_obj: Any, schema_keys: list[str], ms: float | None = None, delta_pct: float | None = None
) -> str:
    """Pretty-print a policy using the order defined by the schema."""
    parts = [f"{k}={getattr(policy_obj, k)}" for k in schema_keys]
    tail = ""
    if ms is not None and delta_pct is not None:
        tail = f" → {ms:.2f} ms (Δ {delta_pct:+.1f}%)"
    return "  " + ", ".join(parts) + tail


def run_benchmark(
    variant: str,
    target_ms: int = DEFAULT_TARGET_MS,
    tolerance: float = DEFAULT_TOLERANCE,
    rounds: int = DEFAULT_ROUNDS,
) -> dict[str, Any]:
    """
    Run a benchmark for the given variant.

    Returns a dict with:
        - best: dict[str, str]  (.env-ready)
        - best_result: BenchmarkResult
        - near: list[BenchmarkResult] (within ±tolerance of target, not including 'best')
        - schema_keys: list[str] (ordering for pretty-print)
    """
    PolicyCls = get_policy_class(variant)
    schema = getattr(PolicyCls, "BENCH_SCHEMA", None)
    if not schema:
        raise RuntimeError(f"Policy '{variant}' does not define BENCH_SCHEMA.")

    schema_keys = list(schema.keys())

    # Silence securitykit warnings during timing (keep tqdm clean)
    kit_logger = logging.getLogger("securitykit")
    prev_level = kit_logger.level
    kit_logger.setLevel(logging.ERROR)

    try:
        results: list[BenchmarkResult] = []
        total = 1
        for values in schema.values():
            total *= len(values)

        with tqdm(total=total, desc=f"Benchmarking {variant}") as bar:
            for combo in _cartesian(schema):
                policy = PolicyCls(**combo)
                hasher = Algorithm(variant, policy)
                elapsed = _measure(policy, hasher, rounds=rounds)
                # store as a "result" with single (averaged) timing for simplicity
                results.append(BenchmarkResult(policy, [elapsed], target_ms))
                bar.update(1)

        analyzer = ResultAnalyzer(schema)
        near_all = analyzer.filter_near(results, target_ms, tolerance=tolerance)
        best_result = (
            analyzer.balanced(near_all) if near_all else analyzer.closest(results, target_ms)
        )

        # Remove the chosen best from "near" list (by identity)
        near = [r for r in near_all if r is not best_result]

        best_combo = {k: getattr(best_result.policy, k) for k in schema_keys}
        logger.info(
            "Best config for %s: %s → %.2f ms (target=%d ms)",
            variant,
            best_combo,
            best_result.median,
            target_ms,
        )

        # Build .env-ready config (all values as str)
        env_config: dict[str, str] = {ENV_VARS["HASH_VARIANT"]: str(variant)}
        env_config.update(
            {f"{variant.upper()}_{k.upper()}": str(v) for k, v in best_combo.items()}
        )

        return {
            "best": env_config,
            "best_result": best_result,
            "near": near,
            "schema_keys": schema_keys,
        }

    finally:
        kit_logger.setLevel(prev_level)


def export_env(config: dict[str, str], filepath: str | Path) -> None:
    """Write benchmark results in .env format."""
    lines = [f"{k}={str(v)}" for k, v in config.items()]
    Path(filepath).write_text("\n".join(lines) + "\n")
    logger.info("Exported benchmark config → %s", filepath)


@click.command()
@click.option("--variant", default=DEFAULTS["HASH_VARIANT"], help="Hash variant to benchmark.")
@click.option("--target-ms", default=DEFAULT_TARGET_MS, help="Target hashing time in ms.")
@click.option("--tolerance", default=DEFAULT_TOLERANCE, help="Tolerance fraction.")
@click.option("--rounds", default=DEFAULT_ROUNDS, help="Timing rounds averaged per combo.")
@click.option("--export-file", type=click.Path(), help="Export best config to a .env file.")
def cli(variant: str, target_ms: int, tolerance: float, rounds: int, export_file: str | None):
    """Run a benchmark for a given hash variant and optionally export the config."""
    result = run_benchmark(variant, target_ms=target_ms, tolerance=tolerance, rounds=rounds)

    # Print best
    click.echo("=== Benchmark Result ===")
    for k, v in result["best"].items():
        click.echo(f"{k}={v}")

    # Print other candidates near target (schema-driven order)
    near: list[BenchmarkResult] = result["near"]
    if near:
        click.echo("\nOther candidates near target:")
        keys = result["schema_keys"]
        for r in near:
            delta = ((r.median - target_ms) / target_ms) * 100.0
            line = _format_policy_line(r.policy, keys, r.median, delta)
            click.echo(line)

    if export_file:
        export_env(result["best"], export_file)


if __name__ == "__main__":
    cli()
