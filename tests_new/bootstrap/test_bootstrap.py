import os
from pathlib import Path

import pytest

from securitykit.bootstrap import ensure_env_config
from securitykit.hashing.policies.argon2 import Argon2Policy


# ---------------------------------------------------------------------------
# Fixtures (unique to bootstrap tests)
# ---------------------------------------------------------------------------

@pytest.fixture
def stub_runner(monkeypatch):
    """
    Monkeypatch BenchmarkRunner.run so we never perform real measurements.
    Returns a predictable result shape compatible with bootstrap.
    """
    class FakeResult:
        def __init__(self, median=123.45):
            self.median = median
            self.policy = Argon2Policy()  # default policy

    def fake_run(self):
        best = {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "3",
            "ARGON2_MEMORY_COST": str(64 * 1024),
            "ARGON2_PARALLELISM": "2",
        }
        fake = FakeResult()
        return {
            "best": best,
            "best_result": fake,
            "near": [],
            "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    from securitykit.bench import runner as runner_mod
    monkeypatch.setattr(runner_mod.BenchmarkRunner, "run", fake_run, raising=True)
    return fake_run


@pytest.fixture
def neutral_bench_schema(monkeypatch):
    """
    Shrink Argon2 BENCH_SCHEMA to a single combination for bootstrap tests.
    """
    monkeypatch.setattr(
        Argon2Policy,
        "BENCH_SCHEMA",
        {
            "time_cost": [3],
            "memory_cost": [64 * 1024],
            "parallelism": [2],
        },
    )
    return Argon2Policy.BENCH_SCHEMA


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_complete_env_no_benchmark(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner, monkeypatch):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["ARGON2_TIME_COST"] = "3"
    os.environ["ARGON2_MEMORY_COST"] = str(64 * 1024)
    os.environ["ARGON2_PARALLELISM"] = "2"

    ensure_env_config()

    assert not Path(".env.local").exists(), "Should not create .env.local when config complete"
    log_text = capture_logs.getvalue().lower()
    assert "incomplete" not in log_text
    assert "generated argon2 hashing config" not in log_text


def test_incomplete_env_auto_benchmark_off(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["AUTO_BENCHMARK"] = "0"
    os.environ["ARGON2_TIME_COST"] = "3"

    ensure_env_config()

    log_text = capture_logs.getvalue().lower()
    assert Path(".env.local").exists() is False
    assert "auto_benchmark=0" in log_text


def test_incomplete_env_auto_benchmark_on_generates_file(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["AUTO_BENCHMARK"] = "1"

    ensure_env_config()

    env_file = Path(".env.local")
    assert env_file.exists(), ".env.local should be generated"
    content = env_file.read_text().splitlines()
    kv = {}
    for line in content:
        if "=" in line and not line.startswith("#"):
            k, v = line.split("=", 1)
            kv[k.strip()] = v.strip()

    assert kv.get("HASH_VARIANT") == "argon2"
    assert "GENERATED_BY" in kv
    assert "GENERATED_SHA256" in kv
    assert not any(k.startswith("PEPPER_") for k in kv.keys())

    log_text = capture_logs.getvalue().lower()
    assert "generated argon2 hashing config" in log_text or "generated" in log_text


def test_integrity_mismatch_warning(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["AUTO_BENCHMARK"] = "1"
    ensure_env_config()
    env_file = Path(".env.local")
    original = env_file.read_text()

    lines = [l for l in original.splitlines() if l]
    mutated = []
    for l in lines:
        if l.startswith("ARGON2_TIME_COST="):
            mutated.append("ARGON2_TIME_COST=999")
        else:
            mutated.append(l)
    env_file.write_text("\n".join(mutated) + "\n")

    ensure_env_config()
    log_text = capture_logs.getvalue().lower()
    assert "integrity mismatch" in log_text


def test_unknown_variant_graceful_exit(chdir_tmp, capture_logs):
    os.environ["HASH_VARIANT"] = "totally_unknown_algo_xyz"
    ensure_env_config()
    assert not Path(".env.local").exists()
    assert "unknown hash_variant" in capture_logs.getvalue().lower()


def test_policy_without_bench_schema_skip(monkeypatch, chdir_tmp, capture_logs, stub_runner):
    from dataclasses import dataclass
    from securitykit.hashing.policy_registry import register_policy

    @register_policy("dummy")
    @dataclass(frozen=True)
    class DummyPolicy:
        def to_dict(self):
            return {}

    os.environ["HASH_VARIANT"] = "dummy"
    ensure_env_config()

    assert not Path(".env.local").exists()
    log_text = capture_logs.getvalue().lower()
    assert "no bench_schema" in log_text or "will not attempt benchmarking" in log_text


def test_no_rebenchmark_if_another_process_finished(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["AUTO_BENCHMARK"] = "1"

    ensure_env_config()
    assert Path(".env.local").exists(), "Expected .env.local after first ensure_env_config()"

    log_text_lower = capture_logs.getvalue().lower()
    first_generated_count = log_text_lower.count("generated argon2 hashing config")

    ensure_env_config()
    log_text_lower2 = capture_logs.getvalue().lower()
    second_generated_count = log_text_lower2.count("generated argon2 hashing config")

    assert first_generated_count >= 1
    assert second_generated_count == first_generated_count


def test_export_excludes_pepper_keys(chdir_tmp, capture_logs, neutral_bench_schema, stub_runner):
    os.environ["HASH_VARIANT"] = "argon2"
    os.environ["AUTO_BENCHMARK"] = "1"
    os.environ["PEPPER_MODE"] = "hmac"
    os.environ["PEPPER_HMAC_KEY"] = "ShouldNotLeak"

    ensure_env_config()

    data = Path(".env.local").read_text()
    assert "PEPPER_MODE" not in data
    assert "PEPPER_HMAC_KEY" not in data
