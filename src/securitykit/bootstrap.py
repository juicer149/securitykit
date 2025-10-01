# securitykit/bootstrap.py
import os
import hashlib
from pathlib import Path
from contextlib import contextmanager

try:
    import portalocker
    HAVE_PORTALOCKER = True
except ImportError:
    HAVE_PORTALOCKER = False

from dotenv import load_dotenv

from securitykit.logging_config import logger
from securitykit.core.policy_registry import get_policy_class
from securitykit.bench.config import BenchmarkConfig
from securitykit.bench.runner import BenchmarkRunner
from securitykit.bench.utils import export_env
from securitykit.version import __version__
from securitykit.config import ENV_VARS, DEFAULTS


# -------------------
# Helpers
# -------------------
@contextmanager
def _file_lock(path: Path):
    if not HAVE_PORTALOCKER:
        yield
        return
    lock_path = str(path) + ".lock"
    with open(lock_path, "w") as f:
        portalocker.lock(f, portalocker.LOCK_EX)
        try:
            yield
        finally:
            portalocker.unlock(f)


def _sha256_of(config: dict[str, str]) -> str:
    items = [f"{k}={v}" for k, v in sorted(config.items())]
    blob = "\n".join(items).encode()
    return hashlib.sha256(blob).hexdigest()


def _validate_generated_block(path: Path):
    """Check integrity of an existing .env.local (GENERATED_SHA256)."""
    if not path.exists():
        return
    try:
        content = path.read_text().splitlines()
    except Exception:
        return
    kv: dict[str, str] = {}
    for line in content:
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        kv[k.strip()] = v.strip()
    recorded = kv.get("GENERATED_SHA256")
    if not recorded:
        return
    tmp = dict(kv)
    tmp.pop("GENERATED_SHA256", None)
    recalculated = _sha256_of(tmp)
    if recorded != recalculated:
        logger.warning(
            "Integrity mismatch for %s (GENERATED_SHA256 differs). File may have been modified.",
            path,
        )


def _bool_env(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).lower() in ("1", "true", "yes", "on")


# -------------------
# Auto-benchmark bootstrap
# -------------------
def ensure_env_config():
    if _bool_env(ENV_VARS["SECURITYKIT_DISABLE_BOOTSTRAP"]):
        logger.info("Bootstrap disabled via SECURITYKIT_DISABLE_BOOTSTRAP=1")
        return

    # Load layering
    load_dotenv(Path(".env"), override=False)
    load_dotenv(Path(".env.local"), override=True)

    # Validate integrity if .env.local exists
    _validate_generated_block(Path(".env.local"))

    variant = os.getenv(ENV_VARS["HASH_VARIANT"], DEFAULTS["HASH_VARIANT"]).lower()
    try:
        policy_cls = get_policy_class(variant)
    except Exception as e:
        logger.error("Unknown HASH_VARIANT=%s – aborting bootstrap (%s).", variant, e)
        return

    bench_schema = getattr(policy_cls, "BENCH_SCHEMA", {})
    required_prefix = variant.upper() + "_"
    required_keys = [f"{required_prefix}{field.upper()}" for field in bench_schema.keys()]

    present = [k for k in required_keys if k in os.environ]
    missing = [k for k in required_keys if k not in os.environ]

    # === Case 1: already complete ===
    if not missing:
        logger.debug("All hashing parameters present for %s.", variant)
        return

    # === Case 2: incomplete (either partial or none) ===
    logger.warning(
        "%s config incomplete (%d present, %d missing). Regenerating full set.",
        variant,
        len(present),
        len(missing),
    )

    # Check AUTO_BENCHMARK
    if not _bool_env(ENV_VARS["AUTO_BENCHMARK"], DEFAULTS["AUTO_BENCHMARK"]):
        env_mode = os.getenv(ENV_VARS["SECURITYKIT_ENV"], DEFAULTS["SECURITYKIT_ENV"])
        lvl = logger.error if env_mode == "production" else logger.warning
        lvl(
            "Incomplete %s config (missing: %s). AUTO_BENCHMARK=0 → benchmark skipped. "
            "Provide env file or enable AUTO_BENCHMARK=1.",
            variant,
            ", ".join(missing),
        )
        return

    # === Benchmark and export ===
    export_path = Path(".env.local")
    with _file_lock(export_path):
        # Double-check after acquiring lock
        if export_path.exists():
            load_dotenv(export_path, override=True)
            if all(k in os.environ for k in required_keys):
                logger.info(
                    "Another process completed bootstrap for %s while waiting on lock. Skipping.",
                    variant,
                )
                return

        target_ms = int(
            os.getenv(
                ENV_VARS["AUTO_BENCHMARK_TARGET_MS"],
                DEFAULTS["AUTO_BENCHMARK_TARGET_MS"],
            )
        )
        try:
            config = BenchmarkConfig(variant=variant, target_ms=target_ms)
            runner = BenchmarkRunner(config)
            result = runner.run()
        except Exception as e:
            logger.error("Benchmark failed for %s: %s. Aborting bootstrap.", variant, e)
            return

        # Start with benchmarked values
        env_config = result["best"]

        # Ensure completeness: merge in policy defaults
        defaults = policy_cls().to_dict()
        for field, value in defaults.items():
            key = f"{variant.upper()}_{field.upper()}"
            env_config.setdefault(key, str(value))

        env_config["GENERATED_BY"] = f"securitykit-bench v{__version__}"
        env_config["GENERATED_SHA256"] = _sha256_of(env_config)

        export_env(env_config, export_path)
        os.environ.update(env_config)
        logger.info(
            "Generated %s config → %s (target=%d ms)", variant, export_path, target_ms
        )
