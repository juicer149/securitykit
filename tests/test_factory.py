# tests/test_factory.py
import pytest
from securitykit.core.factory import SecurityFactory
from securitykit.policies.argon2 import Argon2Policy


def test_factory_missing_required_config():
    """
    If required config values are missing but the policy defines defaults,
    the factory should fall back to defaults instead of raising an error.
    """
    config = {
        "HASH_VARIANT": "argon2",
        # Missing ARGON2_TIME_COST → should fall back to default (2)
        "ARGON2_MEMORY_COST": 65536,
        "ARGON2_PARALLELISM": 2,
        "ARGON2_HASH_LENGTH": 32,
        "ARGON2_SALT_LENGTH": 16,
    }
    factory = SecurityFactory(config)
    policy = factory.get_policy("argon2")
    assert isinstance(policy, Argon2Policy)
    assert policy.time_cost == 2  # updated default


def test_factory_with_all_config():
    """Factory should correctly apply all provided config values, including global pepper."""
    config = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": 5,
        "ARGON2_MEMORY_COST": 131072,
        "ARGON2_PARALLELISM": 4,
        "ARGON2_HASH_LENGTH": 64,
        "ARGON2_SALT_LENGTH": 32,
        "PEPPER": "supersecretpepper",  # 🔑 global pepper now
    }
    factory = SecurityFactory(config)
    policy = factory.get_policy("argon2")
    assert isinstance(policy, Argon2Policy)
    assert policy.time_cost == 5
    assert policy.memory_cost == 131072
    assert policy.hash_length == 64
    assert policy.salt_length == 32

    # Pepper is not part of policy, but injected into the algorithm
    algo = factory.get_algorithm()
    assert algo.impl.pepper == "supersecretpepper"

