# tests/test_bootstrap.py
import os
from pathlib import Path

import pytest
from dotenv import load_dotenv

from securitykit.bootstrap import ensure_env_config
from securitykit.core.policy_registry import list_policies, get_policy_class
from securitykit.config import ENV_VARS


@pytest.fixture(autouse=True)
def temp_env_dir(tmp_path, monkeypatch):
    """
    Fixture som automatiskt byter working directory till en tempdir
    och rensar miljövariabler mellan tester.
    """
    monkeypatch.chdir(tmp_path)

    # Spara undan originalmiljö
    old_env = os.environ.copy()

    yield tmp_path

    # Återställ miljövariabler efter test
    os.environ.clear()
    os.environ.update(old_env)


@pytest.fixture(autouse=True)
def mock_benchmark_runner(monkeypatch):
    """
    Mockar BenchmarkRunner.run så att testerna blir snabba.
    Returnerar variant-specifik fake-benchmark baserat på policyklassens BENCH_SCHEMA.
    """
    def fake_run(self):
        policy_cls = get_policy_class(self.config.variant)
        schema = getattr(policy_cls, "BENCH_SCHEMA", {})

        # bygg "best" dict
        env_config = {"HASH_VARIANT": self.config.variant}
        for field, values in schema.items():
            # välj mittvärdet i schemat som fake
            mid_idx = len(values) // 2
            env_config[f"{self.config.variant.upper()}_{field.upper()}"] = str(values[mid_idx])

        return {
            "best": env_config,
            "best_result": None,
            "near": [],
            "schema_keys": list(schema.keys()),
        }

    monkeypatch.setattr("securitykit.bench.runner.BenchmarkRunner.run", fake_run)
    yield


@pytest.mark.parametrize("variant", list_policies())
def test_bootstrap_regenerates_on_partial_config(monkeypatch, caplog, variant, temp_env_dir):
    """Partial config ska regenereras till komplett .env.local."""

    monkeypatch.setenv(ENV_VARS["AUTO_BENCHMARK"], "1")

    env_file = Path(".env.local")
    env_file.write_text(f"{ENV_VARS['HASH_VARIANT']}={variant}\n")

    ensure_env_config()

    content = env_file.read_text()
    policy_cls = get_policy_class(variant)

    # Alla BENCH_SCHEMA-nycklar ska vara med
    for field in policy_cls.BENCH_SCHEMA.keys():
        assert f"{variant.upper()}_{field.upper()}" in content

    # Metadata ska finnas
    assert "GENERATED_BY" in content
    assert "GENERATED_SHA256" in content

    # Logg ska indikera regeneration
    assert "Regenerating full set" in caplog.text

    # ✅ Extra check: värdena i filen matchar mittvärdet i BENCH_SCHEMA
    for field, values in policy_cls.BENCH_SCHEMA.items():
        expected_value = str(values[len(values) // 2])
        assert f"{variant.upper()}_{field.upper()}={expected_value}" in content


@pytest.mark.parametrize("variant", list_policies())
def test_bootstrap_skips_when_complete_config(monkeypatch, caplog, variant, temp_env_dir):
    """Om configen redan är komplett ska bootstrap inte regenerera något."""

    monkeypatch.setenv(ENV_VARS["AUTO_BENCHMARK"], "1")

    env_file = Path(".env.local")

    # Skapa en komplett config manuellt
    policy_cls = get_policy_class(variant)
    lines = [f"{ENV_VARS['HASH_VARIANT']}={variant}"]
    for field in policy_cls.BENCH_SCHEMA.keys():
        lines.append(f"{variant.upper()}_{field.upper()}=123")
    env_file.write_text("\n".join(lines))

    ensure_env_config()

    assert "Regenerating full set" not in caplog.text


def test_bootstrap_disabled(monkeypatch, caplog, temp_env_dir):
    """Om SECURITYKIT_DISABLE_BOOTSTRAP=1 ska bootstrap inte köras."""

    monkeypatch.setenv(ENV_VARS["SECURITYKIT_DISABLE_BOOTSTRAP"], "1")

    ensure_env_config()

    assert "Bootstrap disabled" in caplog.text


def test_bootstrap_fails_on_unknown_variant(monkeypatch, caplog, temp_env_dir):
    """Om HASH_VARIANT pekar på en okänd policy ska bootstrap logga fel."""

    monkeypatch.setenv(ENV_VARS["HASH_VARIANT"], "doesnotexist")

    ensure_env_config()

    assert "Unknown HASH_VARIANT" in caplog.text
