from securitykit.core.policy_registry import list_policies
from securitykit.core.algorithm_registry import list_algorithms


def test_registered_policies_and_algorithms():
    """
    Ensure only real hash policies/algorithms are registered in the registries.
    PasswordPolicy should NOT be included anymore, since it is standalone.
    """
    policies = list_policies()
    algos = list_algorithms()

    # Argon2 is our only registered hash policy right now
    assert "argon2" in policies
    # Password should NOT be there after refactor
    assert "password" not in policies

    # Algorithms registry should also have argon2
    assert "argon2" in algos

