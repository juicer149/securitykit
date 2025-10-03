from dataclasses import dataclass
from typing import Any

import pytest
from click.testing import CliRunner

from securitykit.bench.cli import cli


@pytest.fixture
def stub_runner_run(monkeypatch):
    """
    Stub BenchmarkRunner.run so the CLI does not execute real timing logic.
    """
    import securitykit.bench.runner as runner_mod

    @dataclass
    class _FakePolicy:
        time_cost: int = 2
        memory_cost: int = 65536
        parallelism: int = 1

    @dataclass
    class _FakeResult:
        policy: Any
        median: float
        delta: float

    def fake_run(self):
        best_policy = _FakePolicy()
        near_policy = _FakePolicy(time_cost=2, memory_cost=65536, parallelism=1)
        best = {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "ARGON2_MEMORY_COST": "65536",
            "ARGON2_PARALLELISM": "1",
        }
        return {
            "best": best,
            "best_result": _FakeResult(policy=best_policy, median=42.0, delta=5.0),
            "near": [_FakeResult(policy=near_policy, median=44.0, delta=10.0)],
            "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    monkeypatch.setattr(runner_mod.BenchmarkRunner, "run", fake_run, raising=True)
    return fake_run


def test_cli_basic_output(stub_runner_run):
    runner = CliRunner()
    result = runner.invoke(cli, ["--variant", "argon2", "--target-ms", "250"])
    assert result.exit_code == 0, result.output
    out = result.output
    assert "=== Benchmark Result ===" in out
    assert "HASH_VARIANT=argon2" in out
    # Near section heading should be present due to stub
    assert "Other candidates near target" in out
    # Pretty-print line should display time_cost etc.
    assert "time_cost=2" in out
    # Arrow / delta formatting branch (Δ symbol)
    assert "Δ" in out


def test_cli_export_file(tmp_path, stub_runner_run):
    export_path = tmp_path / ".env.bench"
    runner = CliRunner()
    result = runner.invoke(
        cli,
        [
            "--variant",
            "argon2",
            "--target-ms",
            "250",
            "--export-file",
            str(export_path),
        ],
    )
    assert result.exit_code == 0, result.output
    assert export_path.exists(), "Export file should have been created."
    content = export_path.read_text()
    assert "HASH_VARIANT=argon2" in content
    assert "ARGON2_TIME_COST=2" in content
    assert "PEPPER_" not in content  # ensure pepper settings are not exported


def test_cli_format_policy_line_edge_case():
    from securitykit.bench.cli import _format_policy_line

    @dataclass
    class P:
        a: int = 1
        b: int = 2

    line = _format_policy_line(P(), ["a", "b"], ms=None, delta_pct=None)
    assert "a=1" in line and "b=2" in line
    # No arrow part since ms/delta are None
    assert "Δ" not in line and "ms" not in line
