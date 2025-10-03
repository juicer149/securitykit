"""
Central configuration constants for SecurityKit.
Defines supported environment variable names and default values.
"""

# Canonical environment variable names (single source of truth).
# Values are the literal env var strings (can be used for doc export, validation, etc.).
ENV_VARS = {
    # Benchmark / bootstrap
    "AUTO_BENCHMARK": "AUTO_BENCHMARK",
    "AUTO_BENCHMARK_TARGET_MS": "AUTO_BENCHMARK_TARGET_MS",
    "SECURITYKIT_DISABLE_BOOTSTRAP": "SECURITYKIT_DISABLE_BOOTSTRAP",
    "SECURITYKIT_ENV": "SECURITYKIT_ENV",

    # Hashing core
    "HASH_VARIANT": "HASH_VARIANT",

    # Pepper subsystem (fully replaces legacy PEPPER_VALUE).
    # All are optional – defaults defined in PepperConfig dataclass.
    "PEPPER_ENABLED": "PEPPER_ENABLED",
    "PEPPER_MODE": "PEPPER_MODE",
    "PEPPER_SECRET": "PEPPER_SECRET",
    "PEPPER_PREFIX": "PEPPER_PREFIX",
    "PEPPER_SUFFIX": "PEPPER_SUFFIX",
    "PEPPER_INTERLEAVE_FREQ": "PEPPER_INTERLEAVE_FREQ",
    "PEPPER_INTERLEAVE_TOKEN": "PEPPER_INTERLEAVE_TOKEN",
    "PEPPER_HMAC_KEY": "PEPPER_HMAC_KEY",
    "PEPPER_HMAC_ALGO": "PEPPER_HMAC_ALGO",
    # Future (rotation/versioning) – reserved:
    # "PEPPER_VERSION": "PEPPER_VERSION",
}

# Defaults for core (pepper uses its own dataclass defaults; we do not
# duplicate them here to avoid drift).
DEFAULTS = {
    "AUTO_BENCHMARK": "0",
    "AUTO_BENCHMARK_TARGET_MS": "250",
    "SECURITYKIT_ENV": "development",
    "HASH_VARIANT": "argon2",
}

# Mapping of hashing variants to their environment prefix.
# Extend only when adding a new algorithm that lacks a Policy.ENV_PREFIX.
HASHING_ENV_PREFIXES = {
    "argon2": "ARGON2_",
    "bcrypt": "BCRYPT_",
    # "scrypt": "SCRYPT_",
}

# Pepper environment keys (handy for documentation or filtering env).
PEPPER_ENV_KEYS = tuple(
    k for k in ENV_VARS.values() if k.startswith("PEPPER_")
)

# Base prefixes to clear in tests (dynamic hashing prefixes added below).
CLEAR_ENV_PREFIXES_BASE = (
    "PASSWORD_",
    "HASH_",            # e.g. HASH_VARIANT
    "PEPPER_",          # all pepper keys
)


def _discover_env_prefixes_from_policies() -> tuple[str, ...]:
    """
    Attempt to derive hashing env prefixes dynamically from registered policies.

    Preference order per variant:
      1) Policy.ENV_PREFIX if present
      2) Static fallback from HASHING_ENV_PREFIXES
      3) Heuristic: f"{variant.upper()}_"

    This avoids adding new prefixes here when new policies/algorithms are registered.
    """
    try:
        # Import locally to avoid import-time cycles
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
                # Keep going if a single policy lookup fails
                continue
        return tuple(sorted(prefixes))
    except Exception:
        # Fallback to static map if registry access fails (e.g., partial import contexts)
        return tuple(HASHING_ENV_PREFIXES.values())


def build_clear_env_prefixes(dynamic: bool = True) -> tuple[str, ...]:
    """
    Return tuple with all prefixes the test suite should wipe between tests.

    If dynamic=True (default), derive hashing prefixes from registered policies.
    If dynamic=False, use the static HASHING_ENV_PREFIXES mapping only.
    """
    if dynamic:
        dynamic_prefixes = _discover_env_prefixes_from_policies()
    else:
        dynamic_prefixes = tuple(HASHING_ENV_PREFIXES.values())
    return CLEAR_ENV_PREFIXES_BASE + dynamic_prefixes
