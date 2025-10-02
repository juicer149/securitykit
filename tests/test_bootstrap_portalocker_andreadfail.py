import importlib
import sys
import types
from pathlib import Path
from securitykit import config as sk_config

def test_bootstrap_without_portalocker(monkeypatch, tmp_path, caplog):
    monkeypatch.chdir(tmp_path)
    # Remove portalocker so except ImportError path executes
    monkeypatch.setitem(sys.modules, "portalocker", None)
    # Force an ImportError next reload
    sys.modules.pop("portalocker", None)

    import securitykit.bootstrap as bootstrap
    importlib.reload(bootstrap)  # triggers HAVE_PORTALOCKER=False

    monkeypatch.setenv("HASH_VARIANT", sk_config.DEFAULTS["HASH_VARIANT"])
    monkeypatch.setenv("AUTO_BENCHMARK", "0")

    # Create unreadable .env.local to hit read failure path (51-57)
    p = Path(".env.local")
    p.write_text("BROKEN")
    # Monkeypatch read_text to raise
    orig_read = Path.read_text
    def boom(self):
        raise OSError("cannot read")
    monkeypatch.setattr(Path, "read_text", boom)

    bootstrap.ensure_env_config()
    # No crash → path covered
    # restore to avoid side-effects
    monkeypatch.setattr(Path, "read_text", orig_read)
