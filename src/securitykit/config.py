"""
Central configuration constants for SecurityKit.
Defines supported environment variable names and default values.
"""

ENV_VARS = {
    "AUTO_BENCHMARK": "AUTO_BENCHMARK",
    "AUTO_BENCHMARK_TARGET_MS": "AUTO_BENCHMARK_TARGET_MS",
    "SECURITYKIT_DISABLE_BOOTSTRAP": "SECURITYKIT_DISABLE_BOOTSTRAP",
    "SECURITYKIT_ENV": "SECURITYKIT_ENV",
    "HASH_VARIANT": "HASH_VARIANT",
    "PEPPER_VALUE": "PEPPER_VALUE",
}

DEFAULTS = {
    "AUTO_BENCHMARK": "0",
    "AUTO_BENCHMARK_TARGET_MS": "250",
    "SECURITYKIT_ENV": "development",
    "HASH_VARIANT": "argon2",
}
