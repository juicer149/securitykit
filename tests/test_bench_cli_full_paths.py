from click.testing import CliRunner
from securitykit.bench.bench import cli


def test_cli_includes_near_and_export(monkeypatch, tmp_path):
    # Patcha run_benchmark så vi får både best och near med en dummy near-post
    fake_best = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "2",
        "ARGON2_MEMORY_COST": "65536",
    }

    class DummyPolicy:
        time_cost = 3
        memory_cost = 65536
        parallelism = 1

    class DummyResult:
        # Minimal attributåtkomst i _format_policy_line
        policy = DummyPolicy()
        median = 10.0

    fake_result_dict = {
        "best": fake_best,
        "best_result": DummyResult(),
        "near": [DummyResult()],
        "schema_keys": ["time_cost", "memory_cost", "parallelism"],
    }

    def fake_run_benchmark(*args, **kwargs):
        return fake_result_dict

    monkeypatch.setattr("securitykit.bench.bench.run_benchmark", fake_run_benchmark)

    export_path = tmp_path / ".env.cli"

    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--variant",
            "argon2",
            "--target-ms",
            "250",
            "--tolerance",
            "0.5",
            "--rounds",
            "1",
            "--export-file",
            str(export_path),
        ],
    )
    assert res.exit_code == 0
    out = res.output
    assert "=== Benchmark Result ===" in out
    assert "HASH_VARIANT=argon2" in out
    assert "Other candidates near target:" in out
    assert export_path.exists()
    exported = export_path.read_text()
    assert "ARGON2_TIME_COST=2" in exported
