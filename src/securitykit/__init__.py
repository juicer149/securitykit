"""
SecurityKit – A modular security toolkit for password hashing and policy enforcement.
"""
import os
from pathlib import Path
from dotenv import load_dotenv

from securitykit.logging_config import logger
from securitykit.core.algorithm import Algorithm
from securitykit.core.factory import SecurityFactory
from securitykit.core.algorithm_registry import (
    register_algorithm,
    list_algorithms,
    get_algorithm_class,
)
from securitykit.core.policy_registry import (
    register_policy,
    list_policies,
    get_policy_class,
)
from securitykit.policies.password import PasswordPolicy
from securitykit.policies.argon2 import Argon2Policy
from securitykit.algorithms import argon2, password  # noqa: F401
from securitykit.exceptions import (
    SecurityKitError,
    ConfigValidationError,
    InvalidPolicyConfig,
)
from securitykit.bench.bench import run_benchmark, export_env


def _ensure_env_config():
    """Ensure hashing config is available, otherwise run benchmark and generate .env.local."""
    # Load .env (default), then override with .env.local if present
    load_dotenv(dotenv_path=Path(".env"), override=False)
    load_dotenv(dotenv_path=Path(".env.local"), override=True)

    variant = os.getenv("HASH_VARIANT", "argon2").lower()
    required_prefix = variant.upper() + "_"

    # Check required keys from policy schema
    policy_cls = get_policy_class(variant)
    bench_schema = getattr(policy_cls, "BENCH_SCHEMA", {})

    missing = [
        f"{required_prefix}{field.upper()}"
        for field in bench_schema.keys()
        if f"{required_prefix}{field.upper()}" not in os.environ
    ]

    if missing:
        logger.warning(
            f"No complete config for {variant} found in .env/.env.local – running benchmark (target ~250ms)."
        )
        config = run_benchmark(variant, target_ms=250)
        export_path = Path(".env.local")
        export_env(config, export_path)
        # Ensure all values are strings before updating os.environ
        os.environ.update({k: str(v) for k, v in config.items()})
        logger.info("Generated and saved %s config → %s", variant, export_path)


# Run automatically at package import
_ensure_env_config()


__all__ = [
    "logger",
    "SecurityFactory",
    "Algorithm",
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",
    "register_policy",
    "list_policies",
    "get_policy_class",
    "PasswordPolicy",
    "Argon2Policy",
    "SecurityKitError",
    "ConfigValidationError",
    "InvalidPolicyConfig",
]
