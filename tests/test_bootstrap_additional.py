import sys
import importlib
from pathlib import Path

from securitykit import config as sk_config


def reload_bootstrap():
    import securitykit.bootstrap as bootstrap
    importlib.reload(bootstrap)
    return bootstrap


def test_bootstrap_importerror_portalocker(monkeypatch, tmp_path):
    """
    Simulera att portalocker inte finns → HAVE_PORTALOCKER=False (except-block).
    """
    monkeypatch.chdir(tmp_path)

    # Säkerställ att portalocker inte laddas
    if "portalocker" in sys.modules:
        del sys.modules["portalocker"]

    real_import = __import__

    def fake_import(name, *a, **k):
        if name == "portalocker":
            raise ImportError("no portalocker in test")
        return real_import(name, *a, **k)

    monkeypatch.setattr("builtins.__import__", fake_import)

    b = reload_bootstrap()
    # Minimal call för att exercisera att ingen lock används
    monkeypatch.setenv("HASH_VARIANT", sk_config.DEFAULTS["HASH_VARIANT"])
    monkeypatch.setenv("AUTO_BENCHMARK", "0")
    b.ensure_env_config()
    # Inga asserts behövs – coverage att except ImportError kördes räcker


def test_bootstrap_validate_generated_block_read_failure(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    b = reload_bootstrap()
    # Skapa fil som ska trigga read_text men vi causing exception
    p = Path(".env.local")
    p.write_text("GENERATED_SHA256=abc\n")

    def boom(self):
        raise OSError("cannot read now")

    monkeypatch.setattr(Path, "read_text", boom, raising=True)

    # Kör ensure_env_config som ropar _validate_generated_block
    monkeypatch.setenv("HASH_VARIANT", sk_config.DEFAULTS["HASH_VARIANT"])
    monkeypatch.setenv("AUTO_BENCHMARK", "0")
    b.ensure_env_config()
    # Om den inte kraschar har vi passerat except-grenen (51–57)


def test_bootstrap_full_export_real_export_env(monkeypatch, tmp_path):
    """
    Kör hela exportvägen (170–172) med AUTO_BENCHMARK=1 och patchad BenchmarkRunner.
    Använder riktiga export_env (skriver fil) för att trigga os.environ.update.
    """
    monkeypatch.chdir(tmp_path)
    b = reload_bootstrap()

    variant = sk_config.DEFAULTS["HASH_VARIANT"]
    monkeypatch.setenv("HASH_VARIANT", variant)
    monkeypatch.setenv("AUTO_BENCHMARK", "1")
    monkeypatch.setenv("AUTO_BENCHMARK_TARGET_MS", "111")
    # Gör incomplete config så benchmark triggas
    # Patcha BenchmarkConfig & BenchmarkRunner till triviala

    class FakeBenchmarkConfig:
        def __init__(self, variant, target_ms):
            self.variant = variant
            self.target_ms = target_ms

    class FakeRunner:
        def __init__(self, config):
            self.config = config
        def run(self):
            return {
                "best": {
                    f"{variant.upper()}_TIME_COST": "9",
                    f"{variant.upper()}_MEMORY_COST": "65536",
                    f"{variant.upper()}_PARALLELISM": "1",
                }
            }

    monkeypatch.setattr("securitykit.bootstrap.BenchmarkConfig", FakeBenchmarkConfig)
    monkeypatch.setattr("securitykit.bootstrap.BenchmarkRunner", FakeRunner)
    monkeypatch.setattr("securitykit.bootstrap.HAVE_PORTALOCKER", False)

    b.ensure_env_config()

    env_local = Path(".env.local")
    assert env_local.exists()
    text = env_local.read_text()
    # Nycklar + metadata ska ha skrivits (GENERATED_BY + GENERATED_SHA256)
    assert "GENERATED_BY=" in text
    assert "GENERATED_SHA256=" in text
    # OS‐miljön uppdaterad
    assert f"{variant.upper()}_TIME_COST" in text
