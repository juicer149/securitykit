# tests/test_factory_policy_dict.py
import os
from securitykit.core.factory import SecurityFactory
from securitykit.core.algorithm import Algorithm
from securitykit.policies.argon2 import Argon2Policy


def test_factory_get_policy_dict_returns_expected_defaults():
    config = {
        "HASH_VARIANT": "argon2",
        # Lämnar tomt → ska plocka defaults från policy
    }

    factory = SecurityFactory(config)
    policy_dict = factory.get_policy_dict("argon2")

    assert isinstance(policy_dict, dict)
    assert "time_cost" in policy_dict
    assert "memory_cost" in policy_dict
    assert "parallelism" in policy_dict
    assert policy_dict["time_cost"] == Argon2Policy().time_cost


def test_algorithm_get_policy_dict_matches_factory():
    config = {"HASH_VARIANT": "argon2"}
    factory = SecurityFactory(config)
    algo = factory.get_algorithm()

    # Hämta från Algorithm direkt
    algo_policy_dict = algo.get_policy_dict()
    factory_policy_dict = factory.get_policy_dict("argon2")

    assert algo_policy_dict == factory_policy_dict
    assert algo_policy_dict["time_cost"] == Argon2Policy().time_cost


def test_get_policy_dict_respects_config_override():
    config = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "5",
        "ARGON2_MEMORY_COST": "32768",  # 32 MiB
        "ARGON2_PARALLELISM": "2",
    }

    factory = SecurityFactory(config)
    policy_dict = factory.get_policy_dict("argon2")

    assert policy_dict["time_cost"] == 5
    assert policy_dict["memory_cost"] == 32768
    assert policy_dict["parallelism"] == 2
