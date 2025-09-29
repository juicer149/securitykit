# tests/test_password_factory.py
import pytest

from securitykit.core.factory import SecurityFactory
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import ConfigValidationError


def test_password_policy_defaults():
    """If no config is provided, PasswordPolicy should load with defaults."""
    factory = SecurityFactory({})
    policy = factory.get_password_policy()
    assert isinstance(policy, PasswordPolicy)
    # Default values from dataclass
    assert policy.min_length == 8
    assert policy.require_upper is True
    assert policy.require_lower is True
    assert policy.require_digit is True
    assert policy.require_special is True


@pytest.mark.parametrize(
    "key,value,expected",
    [
        ("PASSWORD_MIN_LENGTH", "16", 16),
        ("PASSWORD_REQUIRE_UPPER", "false", False),
        ("PASSWORD_REQUIRE_LOWER", "no", False),
        ("PASSWORD_REQUIRE_DIGIT", "on", True),
        ("PASSWORD_REQUIRE_SPECIAL", "off", False),
    ],
)
def test_password_policy_reads_from_config(key, value, expected):
    """PasswordPolicy should correctly parse values from config."""
    config = {key: value}
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()
    assert getattr(policy, key.replace("PASSWORD_", "").lower()) == expected


def test_password_policy_invalid_min_length():
    """Policy should raise ConfigValidationError if min_length is invalid."""
    config = {"PASSWORD_MIN_LENGTH": "0"}  # too short
    factory = SecurityFactory(config)
    with pytest.raises(ConfigValidationError):
        factory.get_password_policy()


def test_password_policy_validation_works():
    """PasswordPolicy should enforce configured rules."""
    config = {
        "PASSWORD_MIN_LENGTH": "8",
        "PASSWORD_REQUIRE_UPPER": "true",
        "PASSWORD_REQUIRE_DIGIT": "true",
        "PASSWORD_REQUIRE_SPECIAL": "true",
    }
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()

    # Should accept a strong password
    policy.validate("StrongP@ssw0rd")

    # Should reject weak passwords
    with pytest.raises(Exception):
        policy.validate("weak")  # too short, missing requirements
