import pytest

from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig, PasswordValidationError

from ..common.helpers import VALID_PASSWORD


def test_validator_accepts_valid_password():
    """
    Happy path: all requirements enabled, strong password passes.
    """
    policy = PasswordPolicy(
        min_length=8,  # below recommended is allowed; warning is fine
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_special=True,
        # complexity_min_length defaults to 12 (soft); allowed even if > min_length
    )
    validator = PasswordValidator(policy)
    # Should not raise
    validator.validate(VALID_PASSWORD)


def test_validator_rejects_too_short():
    """
    Min length failure.
    """
    policy = PasswordPolicy(
        min_length=12,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
    )
    validator = PasswordValidator(policy)
    # Runtime validation error
    with pytest.raises(PasswordValidationError) as e:
        validator.validate("Aa1!abcd")  # length 8 < 12
    assert "at least 12" in str(e.value)


def test_validator_rejects_too_long(monkeypatch):
    """
    Max length failure via class-level PASSWORD_MAX_LENGTH.
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
    # Runtime validation error
    with pytest.raises(PasswordValidationError) as e:
        validator.validate("Aa1!ab")  # length 6 > 5
    assert "max 5" in str(e.value)


@pytest.mark.parametrize(
    "policy_kwargs,password,expected_msg_substr",
    [
        # require_upper
        (
            dict(
                require_upper=True,
                require_lower=False,
                require_digit=False,
                require_special=False,
                min_length=1,
            ),
            "aa1!abcd",
            "uppercase",
        ),
        # require_lower
        (
            dict(
                require_upper=False,
                require_lower=True,
                require_digit=False,
                require_special=False,
                min_length=1,
            ),
            "AA1!ABCD",
            "lowercase",
        ),
        # require_digit
        (
            dict(
                require_upper=False,
                require_lower=False,
                require_digit=True,
                require_special=False,
                min_length=1,
            ),
            "Aa!abcd",
            "digit",
        ),
        # require_special
        (
            dict(
                require_upper=False,
                require_lower=False,
                require_digit=False,
                require_special=True,
                min_length=1,
            ),
            "Aa1abcd",
            "special",
        ),
    ],
)
def test_validator_requirement_failures(policy_kwargs, password, expected_msg_substr):
    policy = PasswordPolicy(**policy_kwargs)
    validator = PasswordValidator(policy)
    # Runtime validation error
    with pytest.raises(PasswordValidationError) as e:
        validator.validate(password)
    # Message should reference the missing class of character
    assert expected_msg_substr in str(e.value).lower()


def test_validator_complexity_threshold_failure_without_special():
    """
    Soft complexity threshold: require 5/5 signals.
    Even if require_special=False (hard rule), complexity still counts 'special'.
    """
    policy = PasswordPolicy(
        min_length=8,
        complexity_min_length=8,
        complexity_rule=5,  # require all 5
        require_upper=True,
        require_lower=True,
        require_digit=True,
        require_special=False,  # not hard-required
    )
    v = PasswordValidator(policy)
    # Runtime validation error
    with pytest.raises(PasswordValidationError) as e:
        v.validate("StrongPass123")  # missing special => only 4/5
    msg = str(e.value).lower()
    assert "complexity insufficient" in msg or "requires ≥5/5" in msg


def test_validator_type_check():
    """
    Validator should enforce the policy type strictly and raise TypeError otherwise.
    """
    with pytest.raises(TypeError):
        PasswordValidator(policy=object())  # not a PasswordPolicy instance


def test_strength_helpers_feedback_and_label():
    policy = PasswordPolicy(min_length=8, complexity_min_length=12, complexity_rule=3)
    v = PasswordValidator(policy)

    label = v.strength_label("StrongPass123!")
    assert label in {"Moderate", "Strong", "Very Strong"}  # depends on evaluator count

    fb = v.feedback("StrongPass123!")
    assert set(fb.keys()) == {"strength", "message", "missing"}
    assert isinstance(fb["message"], str)
