"""
Central configuration constants for SecurityKit.
Defines supported environment variable names and default values.
"""

# Canonical environment variable names (single source of truth)
ENV_VARS = {
    # Benchmark / bootstrap
    "AUTO_BENCHMARK": "AUTO_BENCHMARK",
    "AUTO_BENCHMARK_TARGET_MS": "AUTO_BENCHMARK_TARGET_MS",
    "SECURITYKIT_DISABLE_BOOTSTRAP": "SECURITYKIT_DISABLE_BOOTSTRAP",
    "SECURITYKIT_ENV": "SECURITYKIT_ENV",

    # Hashing core
    "HASH_VARIANT": "HASH_VARIANT",

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

# Defaults
DEFAULTS = {
    "AUTO_BENCHMARK": "0",
    "AUTO_BENCHMARK_TARGET_MS": "250",
    "SECURITYKIT_ENV": "development",
    "HASH_VARIANT": "argon2",
}

HASHING_ENV_PREFIXES = {
    "argon2": "ARGON2_",
    "bcrypt": "BCRYPT_",
}

PEPPER_ENV_KEYS = tuple(k for k in ENV_VARS.values() if k.startswith("PEPPER_"))

CLEAR_ENV_PREFIXES_BASE = (
    "PASSWORD_",
    "HASH_",
    "PEPPER_",
)

# 🔹 Password configuration prefix
PASSWORD_ENV_PREFIX = "PASSWORD_"


def _discover_env_prefixes_from_policies() -> tuple[str, ...]:
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
    if dynamic:
        dynamic_prefixes = _discover_env_prefixes_from_policies()
    else:
        dynamic_prefixes = tuple(HASHING_ENV_PREFIXES.values())
    return CLEAR_ENV_PREFIXES_BASE + dynamic_prefixes
