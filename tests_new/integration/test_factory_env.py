import pytest
from securitykit.hashing.factory import HashingFactory

from ..common.helpers import VALID_PASSWORD


def test_factory_builds_algorithm_with_minimal_env():
    """
    Provide minimal environment variables for Argon2 and ensure hashing works.
    """
    env = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "1",
        "ARGON2_MEMORY_COST": str(8 * 1024),
        "ARGON2_PARALLELISM": "1",
        "ARGON2_HASH_LENGTH": "16",
        "ARGON2_SALT_LENGTH": "16",
    }
    factory = HashingFactory(env)
    algo_wrapper = factory.get_algorithm()
    h = algo_wrapper.hash(VALID_PASSWORD)
    assert algo_wrapper.verify(h, VALID_PASSWORD)


def test_factory_policy_dict(policy_name):
    """
    Ensure HashingFactory.get_policy_dict returns a non-empty dict for each policy.
    """
    env = {"HASH_VARIANT": policy_name}
    factory = HashingFactory(env)
    d = factory.get_policy_dict(policy_name)
    assert isinstance(d, dict)
    assert d
