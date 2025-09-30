import os
import sys
from pathlib import Path
import pytest


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _reset_env():
    """Clear relevant env vars to get a clean state before bootstrap tests."""
    for key in list(os.environ.keys()):
        if key.startswith("ARGON2_") or key in {
            "HASH_VARIANT",
            "AUTO_BENCHMARK",
            "AUTO_BENCHMARK_TARGET_MS",
            "SECURITYKIT_DISABLE_BOOTSTRAP",
            "SECURITYKIT_ENV",
            "PEPPER_VALUE",
        }:
            os.environ.pop(key, None)


def _fresh_import(disable_bootstrap: bool = True):
    """
    Import securitykit in a controlled state.
    disable_bootstrap=True sets SECURITYKIT_DISABLE_BOOTSTRAP=1 so import does not auto-run.
    """
    _reset_env()
    if disable_bootstrap:
        os.environ["SECURITYKIT_DISABLE_BOOTSTRAP"] = "1"
    for m in list(sys.modules):
        if m == "securitykit" or m.startswith("securitykit."):
            sys.modules.pop(m, None)
    import securitykit  # noqa: F401
    return securitykit


def _call_bootstrap(securitykit_module):
    """Force bootstrap run by clearing disable flag and calling internal bootstrap."""
    os.environ.pop("SECURITYKIT_DISABLE_BOOTSTRAP", None)
    securitykit_module._ensure_env_config()  # noqa: SLF001


def make_fake_benchmark(time_cost="2", memory_cost="65536", parallelism="2"):
    """Return a fake run_benchmark function that records calls and returns deterministic config."""
    calls = {"n": 0}

    def fake_run_benchmark(variant: str, target_ms: int = 250, tolerance: float = 0.10, rounds: int = 3):
        calls["n"] += 1
        return {
            "best": {
                "HASH_VARIANT": variant,
                f"{variant.upper()}_TIME_COST": time_cost,
                f"{variant.upper()}_MEMORY_COST": memory_cost,
                f"{variant.upper()}_PARALLELISM": parallelism,
            },
            "near": [],
            "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    return fake_run_benchmark, calls


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _isolate_tmp(monkeypatch, tmp_path):
    """Ensure each test runs in a clean temp directory."""
    monkeypatch.chdir(tmp_path)
    yield


@pytest.fixture
def securitykit():
    return _fresh_import(disable_bootstrap=True)


@pytest.fixture
def patch_benchmark(monkeypatch, securitykit):
    """
    Fixture to patch run_benchmark and export_env in a test.
    Returns a tuple: (calls dict, set_export_env function).
    """
    def _patch(time_cost="2", memory_cost="65536", parallelism="2"):
        fake_run_benchmark, calls = make_fake_benchmark(time_cost, memory_cost, parallelism)

        def fake_export_env(cfg, path):
            Path(path).write_text("\n".join(f"{k}={v}" for k, v in cfg.items()) + "\n")

        monkeypatch.setattr(securitykit, "run_benchmark", fake_run_benchmark, raising=True)
        monkeypatch.setattr(securitykit, "export_env", fake_export_env, raising=True)

        return calls

    return _patch


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_auto_benchmark_no_config(securitykit, caplog):
    caplog.set_level("INFO")
    os.environ["AUTO_BENCHMARK"] = "0"
    _call_bootstrap(securitykit)
    assert not Path(".env.local").exists()
    assert "Incomplete argon2 config" in caplog.text


def test_auto_benchmark_runs_with_patch(securitykit, patch_benchmark, caplog):
    caplog.set_level("INFO")
    calls = patch_benchmark(time_cost="3")

    os.environ["AUTO_BENCHMARK"] = "1"
    _call_bootstrap(securitykit)

    assert calls["n"] == 1
    content = Path(".env.local").read_text()
    assert "HASH_VARIANT=argon2" in content
    assert "ARGON2_TIME_COST=3" in content
    assert "GENERATED_BY=" in content
    assert "GENERATED_SHA256=" in content
    assert "Generated argon2 config" in caplog.text or "generated argon2 config" in caplog.text.lower()


def test_partial_config_triggers_regeneration(securitykit, patch_benchmark):
    calls = patch_benchmark(time_cost="2")

    os.environ["AUTO_BENCHMARK"] = "1"
    os.environ["ARGON2_TIME_COST"] = "9"  # partial / inconsistent
    _call_bootstrap(securitykit)

    assert calls["n"] == 1
    text = Path(".env.local").read_text()
    assert "ARGON2_TIME_COST=2" in text
    assert "ARGON2_MEMORY_COST=65536" in text


def test_integrity_mismatch_warning(securitykit, monkeypatch, caplog):
    caplog.set_level("INFO")

    fake_run_benchmark, _ = make_fake_benchmark()
    def fake_export_env(cfg, path):
        cfg["GENERATED_BY"] = "securitykit-bench vTEST"
        import hashlib
        tmp = dict(cfg)
        items = [f"{k}={v}" for k, v in sorted(tmp.items())]
        cfg["GENERATED_SHA256"] = hashlib.sha256("\n".join(items).encode()).hexdigest()
        Path(path).write_text("\n".join(f"{k}={v}" for k, v in cfg.items()) + "\n")

    monkeypatch.setattr(securitykit, "run_benchmark", fake_run_benchmark, raising=True)
    monkeypatch.setattr(securitykit, "export_env", fake_export_env, raising=True)

    os.environ["AUTO_BENCHMARK"] = "1"
    _call_bootstrap(securitykit)

    # Tamper
    lines = Path(".env.local").read_text().splitlines()
    tampered = [("ARGON2_TIME_COST=999" if l.startswith("ARGON2_TIME_COST=") else l) for l in lines]
    Path(".env.local").write_text("\n".join(tampered) + "\n")

    caplog.clear()
    _call_bootstrap(securitykit)
    assert "Integrity mismatch" in caplog.text


def test_disable_bootstrap_flag_message(caplog):
    _reset_env()
    caplog.set_level("INFO")
    os.environ["SECURITYKIT_DISABLE_BOOTSTRAP"] = "1"
    for m in list(sys.modules):
        if m == "securitykit" or m.startswith("securitykit."):
            sys.modules.pop(m, None)
    import securitykit  # noqa: F401
    assert "Bootstrap disabled via SECURITYKIT_DISABLE_BOOTSTRAP=1" in caplog.text
    assert not Path(".env.local").exists()


def test_production_logs_error(securitykit, caplog):
    caplog.set_level("INFO")
    os.environ["SECURITYKIT_ENV"] = "production"
    os.environ["AUTO_BENCHMARK"] = "0"
    _call_bootstrap(securitykit)
    assert any(rec.levelname == "ERROR" and "Incomplete argon2 config" in rec.message for rec in caplog.records)


def test_subsequent_bootstrap_does_not_rerun(securitykit, patch_benchmark):
    calls = patch_benchmark(time_cost="2")

    os.environ["AUTO_BENCHMARK"] = "1"
    _call_bootstrap(securitykit)
    assert calls["n"] == 1

    # second call should not re-run
    _call_bootstrap(securitykit)
    assert calls["n"] == 1


def test_file_lock_fallback_without_portalocker(monkeypatch, securitykit):
    monkeypatch.setattr(securitykit, "HAVE_PORTALOCKER", False)
    calls = {"n": 0}

    def fake_run_benchmark(*a, **kw):
        calls["n"] += 1
        return {
            "best": {"HASH_VARIANT": "argon2", "ARGON2_TIME_COST": "5", "ARGON2_MEMORY_COST": "65536", "ARGON2_PARALLELISM": "2"},
            "near": [], "schema_keys": ["time_cost", "memory_cost", "parallelism"],
        }

    monkeypatch.setattr(securitykit, "run_benchmark", fake_run_benchmark, raising=True)
    monkeypatch.setattr(securitykit, "export_env", lambda cfg, p: Path(p).write_text("\n".join(f"{k}={v}" for k, v in cfg.items()) + "\n"), raising=True)

    os.environ["AUTO_BENCHMARK"] = "1"
    _call_bootstrap(securitykit)

    text = Path(".env.local").read_text()
    assert "ARGON2_TIME_COST=5" in text
    assert calls["n"] == 1


@pytest.mark.skip(reason="Integration example – enable to run real benchmark (slow).")
def test_real_benchmark_run():
    _reset_env()
    os.environ["AUTO_BENCHMARK"] = "1"
    for m in list(sys.modules):
        if m == "securitykit" or m.startswith("securitykit."):
            sys.modules.pop(m, None)
    import securitykit  # noqa: F401
    assert Path(".env.local").exists()
