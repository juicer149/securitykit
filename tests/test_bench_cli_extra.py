import sys
import runpy
from click.testing import CliRunner

from securitykit.bench.cli import _format_policy_line, cli


class DummyPolicy:
    def __init__(self, a=1, b=2):
        self.a = a
        self.b = b


def test_format_policy_line_branches():
    p = DummyPolicy(a=5, b=10)
    keys = ["a", "b"]

    # Gren utan tail
    line_plain = _format_policy_line(p, keys)
    assert "a=5" in line_plain and "b=10" in line_plain and "→" not in line_plain

    # Gren med tail
    line_timed = _format_policy_line(p, keys, ms=12.3456, delta_pct=-3.2101)
    assert "→ 12.35 ms" in line_timed
    assert "Δ -3.2%" in line_timed


def test_cli_near_branch_and_export(monkeypatch, tmp_path):
    # Patch BenchmarkRunner.run (används av bench/cli.py)
    class FakePolicy:
        a = 1
        b = 2

    class FakeResultObj:
        policy = FakePolicy()
        median = 42.0  # för delta-beräkning

    fake_result = {
        "best": {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "3",
        },
        "best_result": FakeResultObj(),
        "near": [FakeResultObj()],  # triggar near-utskrift
        "schema_keys": ["a", "b"],
    }

    def fake_run(self):
        return fake_result

    monkeypatch.setattr("securitykit.bench.cli.BenchmarkRunner.run", fake_run)

    export_path = tmp_path / ".env.cli.extra"
    runner = CliRunner()
    res = runner.invoke(
        cli,
        [
            "--variant",
            "argon2",
            "--target-ms",
            "200",
            "--tolerance",
            "0.2",
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
    assert "Other candidates near target:" in out  # near-branch
    assert export_path.exists()
    assert "HASH_VARIANT=argon2" in export_path.read_text()


def test_cli_main_guard_no_system_exit(monkeypatch):
    """
    Täck 'if __name__ == __main__' kodväg utan att låta SystemExit bubbla.
    Vi anropar cli.main(standalone_mode=False) direkt istället för run_module + sys.exit.
    """
    class FakePolicy:
        a = 1
        b = 2

    class FakeResultObj:
        policy = FakePolicy()
        median = 10.0

    fake_result = {
        "best": {"HASH_VARIANT": "argon2"},
        "best_result": FakeResultObj(),
        "near": [],
        "schema_keys": ["a", "b"],
    }

    def fake_run(self):
        return fake_result

    monkeypatch.setattr("securitykit.bench.cli.BenchmarkRunner.run", fake_run)
    # Stilla utskrift
    monkeypatch.setattr("click.echo", lambda *a, **k: None)

    # Anropa kommandot utan standalone_mode → ingen SystemExit
    cli.main(args=[], standalone_mode=False)
