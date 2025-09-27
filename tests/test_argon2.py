import pytest
from securitykit.policies.argon2 import Argon2Policy, ARGON2_MIN_TIME_COST
from securitykit.exceptions import InvalidPolicyConfig


def test_argon2_policy_valid_defaults():
    policy = Argon2Policy()
    assert policy.time_cost >= ARGON2_MIN_TIME_COST


def test_argon2_policy_invalid_time_cost():
    with pytest.raises(InvalidPolicyConfig):
        Argon2Policy(time_cost=0)
