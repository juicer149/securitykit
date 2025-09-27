import pytest
from securitykit.core.factory import SecurityFactory
from securitykit.policies.argon2 import Argon2Policy
from securitykit.policies.password import PasswordPolicy
from securitykit.core.algorithm import Algorithm
from securitykit.exceptions import UnknownAlgorithmError


def test_factory_missing_required_config():
    """
    If required config values are missing but the policy defines defaults,
    the factory should fall back to defaults instead of raising an error.
    """
    config = {
        "HASH_VARIANT": "argon2",
        # Missing ARGON2_TIME_COST → should fall back to default (6)
        "ARGON2_MEMORY_COST": 65536,
        "ARGON2_PARALLELISM": 2,
        "ARGON2_HASH_LENGTH": 32,
        "ARGON2_SALT_LENGTH": 16,
    }
    factory = SecurityFactory(config)
    policy = factory.get_policy("argon2")
    assert isinstance(policy, Argon2Policy)
    assert policy.time_cost == 6  # default applied
