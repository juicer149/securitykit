# securitykit/bench/cli.py
import click
from pathlib import Path

from securitykit.config import DEFAULTS
from securitykit.bench.config import (
    BenchmarkConfig,
    DEFAULT_TARGET_MS,
    DEFAULT_TOLERANCE,
    DEFAULT_ROUNDS,
)
from securitykit.bench.runner import BenchmarkRunner
from securitykit.bench.engine import BenchmarkResult
from securitykit.bench.utils import export_env   # ✅ importera här
from securitykit.logging_config import logger


def _format_policy_line(policy_obj, schema_keys, ms=None, delta_pct=None) -> str:
    """Pretty-print a policy with timing and delta info."""
    parts = [f"{k}={getattr(policy_obj, k)}" for k in schema_keys]
    tail = f" → {ms:.2f} ms (Δ {delta_pct:+.1f}%)" if ms and delta_pct else ""
    return "  " + ", ".join(parts) + tail


@click.command()
@click.option(
    "--variant",
    default=DEFAULTS["HASH_VARIANT"],
    help="Hash variant to benchmark.",
)
@click.option(
    "--target-ms",
    default=DEFAULT_TARGET_MS,
    help="Target hashing time in ms.",
)
@click.option(
    "--tolerance",
    default=DEFAULT_TOLERANCE,
    help="Tolerance fraction (default ±15%).",
)
@click.option(
    "--rounds",
    default=DEFAULT_ROUNDS,
    help="Timing rounds averaged per combo.",
)
@click.option(
    "--export-file",
    type=click.Path(),
    help="Export best config to a .env file.",
)
def cli(
    variant: str,
    target_ms: int,
    tolerance: float,
    rounds: int,
    export_file: str | None,
):
    """Run a benchmark for a given hash variant and optionally export the config."""

    config = BenchmarkConfig(
        variant=variant,
        target_ms=target_ms,
        tolerance=tolerance,
        rounds=rounds,
    )
    runner = BenchmarkRunner(config)
    result = runner.run()

    # Print best config
    click.echo("=== Benchmark Result ===")
    for k, v in result["best"].items():
        click.echo(f"{k}={v}")

    # Print other candidates near target
    near: list[BenchmarkResult] = result["near"]
    if near:
        click.echo("\nOther candidates near target:")
        keys = result["schema_keys"]
        for r in near:
            delta = ((r.median - target_ms) / target_ms) * 100.0
            line = _format_policy_line(r.policy, keys, r.median, delta)
            click.echo(line)

    # Optionally export to .env
    if export_file:
        export_env(result["best"], export_file)


if __name__ == "__main__":
    cli()
