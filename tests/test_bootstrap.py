import os
import importlib
from pathlib import Path
from textwrap import dedent

import pytest
from securitykit import config as sk_config


def reload_bootstrap():
    import securitykit.bootstrap as bootstrap
    importlib.reload(bootstrap)
    return bootstrap


@pytest.fixture(autouse=True)
def isolated_cwd(monkeypatch, tmp_path):
    monkeypatch.chdir(tmp_path)
    yield


def test_bootstrap_disabled(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("SECURITYKIT_DISABLE_BOOTSTRAP", "1")
    monkeypatch.setenv("HASH_VARIANT", variant)
    b = reload_bootstrap()
    b.ensure_env_config()
    assert any("Bootstrap disabled" in r.message for r in caplog.records)


def test_bootstrap_complete_config_no_action(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv(f"{variant.upper()}_TIME_COST", "2")
    monkeypatch.setenv(f"{variant.upper()}_MEMORY_COST", "65536")
    monkeypatch.setenv(f"{variant.upper()}_PARALLELISM", "1")

    b = reload_bootstrap()
    b.ensure_env_config()
    assert not any("Regenerating full set" in r.message for r in caplog.records)


def test_bootstrap_integrity_mismatch_warning(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    content = dedent(
        f"""
        {variant.upper()}_TIME_COST=2
        {variant.upper()}_MEMORY_COST=65536
        {variant.upper()}_PARALLELISM=1
        GENERATED_SHA256=bogus
        """
    ).strip() + "\n"
    Path(".env.local").write_text(content)
    b = reload_bootstrap()
    b.ensure_env_config()
    assert any("Integrity mismatch" in r.message for r in caplog.records)


def test_bootstrap_incomplete_auto_benchmark_off_dev(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv("AUTO_BENCHMARK", "0")
    monkeypatch.setenv("SECURITYKIT_ENV", "development")
    b = reload_bootstrap()
    b.ensure_env_config()
    assert any("benchmark skipped" in r.message for r in caplog.records)


def test_bootstrap_incomplete_auto_benchmark_off_production(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv("AUTO_BENCHMARK", "0")
    monkeypatch.setenv("SECURITYKIT_ENV", "production")
    b = reload_bootstrap()
    b.ensure_env_config()
    assert any(r.levelname == "ERROR" and "benchmark skipped" in r.message for r in caplog.records)


def test_bootstrap_runs_benchmark_and_exports_env(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv("AUTO_BENCHMARK", "1")
    monkeypatch.setenv("AUTO_BENCHMARK_TARGET_MS", "123")
    b = reload_bootstrap()

    created = {}

    class FakeBenchmarkConfig:
        def __init__(self, variant, target_ms):
            self.variant = variant
            self.target_ms = target_ms

    class FakeRunner:
        def __init__(self, config):
            pass
        def run(self):
            return {
                "best": {
                    f"{variant.upper()}_TIME_COST": "3",
                    f"{variant.upper()}_MEMORY_COST": "65536",
                    f"{variant.upper()}_PARALLELISM": "1",
                }
            }

    def fake_export_env(cfg, path):
        created["cfg"] = dict(cfg)
        created["path"] = Path(path)
        lines = [f"{k}={v}" for k, v in cfg.items()]
        created["path"].write_text("\n".join(lines) + "\n")

    monkeypatch.setattr("securitykit.bootstrap.BenchmarkConfig", FakeBenchmarkConfig)
    monkeypatch.setattr("securitykit.bootstrap.BenchmarkRunner", FakeRunner)
    monkeypatch.setattr("securitykit.bootstrap.export_env", fake_export_env)
    monkeypatch.setattr("securitykit.bootstrap.HAVE_PORTALOCKER", False)

    b.ensure_env_config()
    cfg = created["cfg"]
    assert f"{variant.upper()}_HASH_LENGTH" in cfg
    assert f"{variant.upper()}_SALT_LENGTH" in cfg
    assert "GENERATED_SHA256" in cfg


def test_bootstrap_concurrent_generation_detected(monkeypatch, caplog):
    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv("AUTO_BENCHMARK", "1")
    b = reload_bootstrap()

    required_keys = {
        f"{variant.upper()}_TIME_COST": "2",
        f"{variant.upper()}_MEMORY_COST": "65536",
        f"{variant.upper()}_PARALLELISM": "1",
        f"{variant.upper()}_HASH_LENGTH": "32",
        f"{variant.upper()}_SALT_LENGTH": "16",
    }

    def fake_lock(path):
        class _Ctx:
            def __enter__(self_inner):
                lines = [f"{k}={v}" for k, v in required_keys.items()]
                Path(path).write_text("\n".join(lines) + "\n")
            def __exit__(self_inner, exc_type, exc, tb):
                return False
        return _Ctx()

    monkeypatch.setattr("securitykit.bootstrap._file_lock", fake_lock)
    monkeypatch.setattr("securitykit.bootstrap.HAVE_PORTALOCKER", False)
    b.ensure_env_config()
    assert any("Another process completed bootstrap" in r.message for r in caplog.records)


def test_bootstrap_unknown_variant_logs_error(monkeypatch, caplog):
    monkeypatch.setenv("HASH_VARIANT", "totallyunknown")
    monkeypatch.setenv("AUTO_BENCHMARK", "0")
    b = reload_bootstrap()
    b.ensure_env_config()
    assert any("Unknown HASH_VARIANT" in r.message for r in caplog.records)
