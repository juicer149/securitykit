import pytest

from securitykit import config
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing import algorithm_registry
from securitykit.exceptions import UnknownAlgorithmError


def test_get_policy_and_dict():
    default_variant = config.DEFAULTS["HASH_VARIANT"]

    config_map = {
        "HASH_VARIANT": default_variant,
        f"{default_variant.upper()}_TIME_COST": 3,
    }
    factory = HashingFactory(config_map)

    policy = factory.get_policy(default_variant)
    assert isinstance(policy, Argon2Policy)
    assert policy.time_cost == 3

    d = factory.get_policy_dict(default_variant)
    assert "time_cost" in d
    assert d["time_cost"] == 3


def test_get_algorithm_with_pepper():
    default_variant = config.DEFAULTS["HASH_VARIANT"]
    config_map = {
        "HASH_VARIANT": default_variant,
        "PEPPER_VALUE": "SECRET123",
        f"{default_variant.upper()}_TIME_COST": 2,
    }
    factory = HashingFactory(config_map)

    algo = factory.get_algorithm()
    assert isinstance(algo, Algorithm)
    hashed = algo.hash("mypassword")
    assert isinstance(hashed, str)
    assert hashed.startswith(f"${default_variant}")


def test_get_algorithm_default_variant():
    default_variant = config.DEFAULTS["HASH_VARIANT"]
    factory = HashingFactory({})
    algo = factory.get_algorithm()
    assert isinstance(algo, Algorithm)
    hashed = algo.hash("anotherpass")
    assert isinstance(hashed, str)
    assert hashed.startswith(f"${default_variant}")


# --- NYTT INTEGRATIONSTEST ---
def test_integration_with_factory_and_argon2():
    """
    Integration: säkerställ att vi kan läsa policy med override via factory + discovery.
    """
    from securitykit import config as sk_config

    default_variant = sk_config.DEFAULTS["HASH_VARIANT"]  # vanligtvis 'argon2'
    cfg = {
        "HASH_VARIANT": default_variant,
        f"{default_variant.upper()}_TIME_COST": "3",  # str → int parse
    }
    factory = HashingFactory(cfg)
    policy = factory.get_policy(default_variant)
    assert isinstance(policy, Argon2Policy)
    assert policy.time_cost == 3


def test_registry_isolation_between_tests():
    # Sabotage
    algorithm_registry._algorithm_registry._registry.clear()
    from securitykit.hashing.algorithm_registry import get_algorithm_class
    with pytest.raises(UnknownAlgorithmError):
        get_algorithm_class("argon2")


def test_registry_restored_after_tamper():
    from securitykit.hashing.algorithm_registry import get_algorithm_class
    algo_cls = get_algorithm_class("argon2")
    assert algo_cls.__name__ == "Argon2"
