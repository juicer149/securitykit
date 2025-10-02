from pathlib import Path
from click.testing import CliRunner

from securitykit.bench.cli import cli
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.algorithm import Algorithm


def test_cli_runs_and_prints(monkeypatch):
    Policy = get_policy_class("argon2")
    original_schema = Policy.BENCH_SCHEMA
    Policy.BENCH_SCHEMA = {"time_cost": [2], "memory_cost": [65536], "parallelism": [1]}

    # Patch Algorithm.hash for speed
    def fast_hash(self, password: str):
        return "x"

    monkeypatch.setattr(Algorithm, "hash", fast_hash, raising=True)

    # Patch BenchmarkRunner.run to avoid timing logic entirely
    def fake_run(self):
        return {
            "best": {
                "HASH_VARIANT": "argon2",
                "ARGON2_TIME_COST": "2",
                "ARGON2_MEMORY_COST": "65536",
                "ARGON2_PARALLELISM": "1",
            },
            "best_result": object(),
            "near": [],
            "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    monkeypatch.setattr("securitykit.bench.cli.BenchmarkRunner.run", fake_run)

    runner = CliRunner()
    result = runner.invoke(cli, ["--variant", "argon2"])
    assert result.exit_code == 0
    assert "=== Benchmark Result ===" in result.output
    assert "HASH_VARIANT=argon2" in result.output

    Policy.BENCH_SCHEMA = original_schema


def test_cli_export_file(monkeypatch, tmp_path):
    Policy = get_policy_class("argon2")
    original_schema = Policy.BENCH_SCHEMA
    Policy.BENCH_SCHEMA = {"time_cost": [2], "memory_cost": [65536], "parallelism": [1]}

    def fake_run(self):
        return {
            "best": {
                "HASH_VARIANT": "argon2",
                "ARGON2_TIME_COST": "2",
                "ARGON2_MEMORY_COST": "65536",
                "ARGON2_PARALLELISM": "1",
            },
            "best_result": object(),
            "near": [],
            "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    monkeypatch.setattr("securitykit.bench.cli.BenchmarkRunner.run", fake_run)

    export_path = tmp_path / ".env.bench"
    runner = CliRunner()
    result = runner.invoke(cli, ["--variant", "argon2", "--export-file", str(export_path)])
    assert result.exit_code == 0
    assert export_path.exists()
    content = export_path.read_text()
    assert "HASH_VARIANT=argon2" in content

    Policy.BENCH_SCHEMA = original_schema
