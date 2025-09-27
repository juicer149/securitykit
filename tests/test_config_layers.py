from securitykit.core.policy_registry import list_policies
from securitykit.core.algorithm_registry import list_algorithms


def test_registered_policies_and_algorithms():
    policies = list_policies()
    algos = list_algorithms()

    assert "password" in policies
    assert "argon2" in policies
    assert "argon2" in algos

