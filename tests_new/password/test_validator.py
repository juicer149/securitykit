import pytest

from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig

from ..common.helpers import VALID_PASSWORD


def test_validator_accepts_valid_password():
    """
    Happy path: all requirements enabled, strong password passes.
    """
    policy = PasswordPolicy(
        min_length=8,
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_special=True,
    )
    validator = PasswordValidator(policy)
    # Should not raise
    validator.validate(VALID_PASSWORD)


def test_validator_rejects_too_short():
    """
    Covers line 19: min length failure.
    """
    policy = PasswordPolicy(
        min_length=12,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
    )
    validator = PasswordValidator(policy)
    with pytest.raises(InvalidPolicyConfig) as e:
        validator.validate("Aa1!abcd")  # length 8 < 12
    assert "at least 12" in str(e.value)


def test_validator_rejects_too_long(monkeypatch):
    """
    Covers line 23: max length failure via class-level PASSWORD_MAX_LENGTH.
    We monkeypatch the class attribute to a small value to avoid hard-coding defaults.
    """
    policy = PasswordPolicy(
        min_length=1,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
    )
    # Ensure PASSWORD_MAX_LENGTH is small so an ordinary string exceeds it
    monkeypatch.setattr(type(policy), "PASSWORD_MAX_LENGTH", 5, raising=False)

    validator = PasswordValidator(policy)
    with pytest.raises(InvalidPolicyConfig) as e:
        validator.validate("Aa1!ab")  # length 6 > 5
    assert "max 5" in str(e.value)


@pytest.mark.parametrize(
    "policy_kwargs,password,expected_msg_substr",
    [
        # Covers line 28: require_upper
        (dict(require_upper=True, require_lower=False, require_digit=False, require_special=False, min_length=1),
         "aa1!abcd", "uppercase"),
        # Covers line 30: require_lower
        (dict(require_upper=False, require_lower=True, require_digit=False, require_special=False, min_length=1),
         "AA1!ABCD", "lowercase"),
        # Covers line 32: require_digit
        (dict(require_upper=False, require_lower=False, require_digit=True, require_special=False, min_length=1),
         "Aa!abcd", "digit"),
        # Covers line 34: require_special
        (dict(require_upper=False, require_lower=False, require_digit=False, require_special=True, min_length=1),
         "Aa1abcd", "special"),
    ],
)
def test_validator_requirement_failures(policy_kwargs, password, expected_msg_substr):
    policy = PasswordPolicy(**policy_kwargs)
    validator = PasswordValidator(policy)
    with pytest.raises(InvalidPolicyConfig) as e:
        validator.validate(password)
    # Message should reference the missing class of character
    assert expected_msg_substr in str(e.value).lower()
