import pytest
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import InvalidPolicyConfig


def test_password_policy_valid():
    policy = PasswordPolicy(min_length=8)
    # should not raise
    policy.validate("GoodPass123!")


@pytest.mark.parametrize("password", ["short", "noupper123!", "NOLOWER123!", "NoDigit!", "NoSpecial123"])
def test_password_policy_invalid(password):
    policy = PasswordPolicy(min_length=8)
    with pytest.raises(InvalidPolicyConfig):
        policy.validate(password)
