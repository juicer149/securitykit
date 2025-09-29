# tests/test_password_policy.py
import pytest
from securitykit.policies.password import (
    PasswordPolicy,
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_RECOMMENDED_MIN_LENGTH,
)
from securitykit.exceptions import InvalidPolicyConfig


def test_password_policy_defaults_warns_below_recommended(caplog):
    caplog.set_level("WARNING")
    policy = PasswordPolicy()  # default min_length = 8
    assert policy.min_length == 8
    assert any(str(PASSWORD_RECOMMENDED_MIN_LENGTH) in m for m in caplog.messages)


def test_password_policy_rejects_too_short_min_length():
    with pytest.raises(InvalidPolicyConfig):
        PasswordPolicy(min_length=PASSWORD_MIN_LENGTH - 1)


def test_password_policy_rejects_too_high_min_length():
    with pytest.raises(InvalidPolicyConfig):
        PasswordPolicy(min_length=PASSWORD_MAX_LENGTH + 1)


def test_password_policy_accepts_normal_range():
    policy = PasswordPolicy(min_length=16)
    assert policy.min_length == 16


def test_password_policy_validation_too_short():
    policy = PasswordPolicy(min_length=8, require_upper=False, require_special=False)
    with pytest.raises(InvalidPolicyConfig):
        policy.validate("short")


def test_password_policy_validation_too_long():
    policy = PasswordPolicy(min_length=8, require_upper=False, require_special=False)
    too_long = "x" * (PASSWORD_MAX_LENGTH + 1)
    with pytest.raises(InvalidPolicyConfig):
        policy.validate(too_long)


@pytest.mark.parametrize("password", ["ValidPass123!", "AnotherOne9$"])
def test_password_policy_validation_success(password):
    policy = PasswordPolicy(min_length=8)
    policy.validate(password)
