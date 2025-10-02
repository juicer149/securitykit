import pytest
from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig


def build_validator(**overrides):
    policy = PasswordPolicy(**overrides)
    return PasswordValidator(policy)


def test_validator_accepts_valid_password():
    v = build_validator(min_length=6)
    # Must contain upper, lower, digit, special by default
    v.validate("Aa1!xx")  # Should not raise


@pytest.mark.parametrize(
    "password,expected_substring",
    [
        ("Short1!", "at least"),                      # too short
        ("A" * (PasswordPolicy.PASSWORD_MAX_LENGTH + 1), "too long"),  # too long
        ("alllower1!", "uppercase"),
        ("ALLUPPER1!", "lowercase"),
        ("NoDigits!!", "digit"),
        ("NoSpecial1", "special"),
    ],
)
def test_validator_failures(password, expected_substring):
    v = build_validator(min_length=8)
    with pytest.raises(InvalidPolicyConfig) as exc:
        v.validate(password)
    assert expected_substring in str(exc.value)


def test_validator_with_require_flags_disabled():
    # Disable all complexity requirements: only length matters now
    v = build_validator(
        min_length=4,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
    )
    # Should pass even though it fails all original complexity checks
    v.validate("aaaa")


def test_validator_edge_upper_boundary():
    # Exactly max length should pass if other requirements satisfied
    v = build_validator(min_length=8)
    pw = "A" + "a" * (PasswordPolicy.PASSWORD_MAX_LENGTH - 4) + "1!"
    v.validate(pw)


def test_validator_min_length_enforced():
    v = build_validator(min_length=12)
    with pytest.raises(InvalidPolicyConfig):
        v.validate("Aa1!short")
