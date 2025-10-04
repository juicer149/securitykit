"""
Central configuration constants for SecurityKit.
Defines supported environment variable names and default values.
"""

from __future__ import annotations

from typing import Tuple

# Canonical environment variable names (single source of truth)
ENV_VARS = {
    # Benchmark / bootstrap
    "AUTO_BENCHMARK": "AUTO_BENCHMARK",
    "AUTO_BENCHMARK_TARGET_MS": "AUTO_BENCHMARK_TARGET_MS",
    "SECURITYKIT_DISABLE_BOOTSTRAP": "SECURITYKIT_DISABLE_BOOTSTRAP",
    "SECURITYKIT_ENV": "SECURITYKIT_ENV",

    # Hashing core
    "HASH_VARIANT": "HASH_VARIANT",

    # Per-variant global overrides (algorithm-specific but not part of policy dataclass)
    # scrypt OpenSSL memory cap in bytes; default set in DEFAULTS below
    "SCRYPT_MAXMEM": "SCRYPT_MAXMEM",

    # Pepper subsystem
    "PEPPER_ENABLED": "PEPPER_ENABLED",
    "PEPPER_MODE": "PEPPER_MODE",
    "PEPPER_SECRET": "PEPPER_SECRET",
    "PEPPER_PREFIX": "PEPPER_PREFIX",
    "PEPPER_SUFFIX": "PEPPER_SUFFIX",
    "PEPPER_INTERLEAVE_FREQ": "PEPPER_INTERLEAVE_FREQ",
    "PEPPER_INTERLEAVE_TOKEN": "PEPPER_INTERLEAVE_TOKEN",
    "PEPPER_HMAC_KEY": "PEPPER_HMAC_KEY",
    "PEPPER_HMAC_ALGO": "PEPPER_HMAC_ALGO",
}

# Defaults chosen to run with minimal core (no extras required).
# If you prefer Argon2 as default, change HASH_VARIANT to "argon2".
DEFAULTS = {
    "AUTO_BENCHMARK": "0",
    "AUTO_BENCHMARK_TARGET_MS": "250",
    "SECURITYKIT_ENV": "development",
    "HASH_VARIANT": "scrypt",
    # scrypt default: generous cap to avoid spurious "memory limit exceeded"
    "SCRYPT_MAXMEM": str(512 * 1024 * 1024),  # 512 MiB
}

# Static fallback prefixes for hashing policies (used when dynamic discovery fails)
HASHING_ENV_PREFIXES = {
    "argon2": "ARGON2_",
    "bcrypt": "BCRYPT_",
    "scrypt": "SCRYPT_",
    "werkzeug_pbkdf2": "WERKZEUG_PBKDF2_",
}

# Optional: canonical per-variant policy parameter keys (useful for docs/export)
POLICY_PARAM_KEYS: dict[str, Tuple[str, ...]] = {
    "argon2": (
        "ARGON2_TIME_COST",
        "ARGON2_MEMORY_COST",
        "ARGON2_PARALLELISM",
        "ARGON2_HASH_LENGTH",
        "ARGON2_SALT_LENGTH",
    ),
    "bcrypt": (
        "BCRYPT_ROUNDS",
    ),
    "scrypt": (
        "SCRYPT_N",
        "SCRYPT_R",
        "SCRYPT_P",
        "SCRYPT_SALT_LENGTH",
        "SCRYPT_HASH_LENGTH",
    ),
    "werkzeug_pbkdf2": (
        "WERKZEUG_PBKDF2_METHOD",
        "WERKZEUG_PBKDF2_ITERATIONS",
        "WERKZEUG_PBKDF2_SALT_LENGTH",
    ),
}

PEPPER_ENV_KEYS = tuple(k for k in ENV_VARS.values() if k.startswith("PEPPER_"))

# Base prefixes to clear when scrubbing env for secure export
CLEAR_ENV_PREFIXES_BASE = (
    "PASSWORD_",
    "HASH_",
    "PEPPER_",
)

# Password configuration prefix (hard rules + complexity)
PASSWORD_ENV_PREFIX = "PASSWORD_"


def _discover_env_prefixes_from_policies() -> tuple[str, ...]:
    """
    Attempt to discover ENV_PREFIX for all registered policies dynamically.
    Falls back to static HASHING_ENV_PREFIXES if discovery fails.
    """
    try:
        from securitykit.hashing import policy_registry

        prefixes: set[str] = set()
        for variant in policy_registry.list_policies():
            try:
                Policy = policy_registry.get_policy_class(variant)
                prefix = getattr(Policy, "ENV_PREFIX", None)
                if not prefix:
                    prefix = HASHING_ENV_PREFIXES.get(variant, f"{variant.upper()}_")
                prefixes.add(prefix)
            except Exception:
                continue
        return tuple(sorted(prefixes))
    except Exception:
        return tuple(HASHING_ENV_PREFIXES.values())


def build_clear_env_prefixes(dynamic: bool = True) -> tuple[str, ...]:
    """
    Build the tuple of prefixes that should be cleared from exported env snapshots
    (e.g., when generating integrity-protected example configs).
    When dynamic=True, consult registered policies for their ENV_PREFIX.
    """
    if dynamic:
        dynamic_prefixes = _discover_env_prefixes_from_policies()
    else:
        dynamic_prefixes = tuple(HASHING_ENV_PREFIXES.values())
    return CLEAR_ENV_PREFIXES_BASE + dynamic_prefixes
