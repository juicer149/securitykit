# tests/test_password_factory.py
import pytest

from securitykit.core.factory import SecurityFactory
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import ConfigValidationError


def test_password_policy_disabled_by_default():
    factory = SecurityFactory({})
    policy = factory.get_password_policy()
    assert policy is None


def test_password_policy_enabled_with_defaults():
    config = {"PASSWORD_SECURITY": "true"}
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()

    assert isinstance(policy, PasswordPolicy)
    # default values från dataclass
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
    config = {
        "PASSWORD_SECURITY": "true",
        key: value,
    }
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()
    assert getattr(policy, key.replace("PASSWORD_", "").lower()) == expected


def test_password_policy_invalid_min_length():
    config = {
        "PASSWORD_SECURITY": "true",
        "PASSWORD_MIN_LENGTH": "0",  # för kort
    }
    factory = SecurityFactory(config)
    with pytest.raises(ConfigValidationError):
        factory.get_password_policy()


def test_password_policy_validation_works():
    config = {
        "PASSWORD_SECURITY": "true",
        "PASSWORD_MIN_LENGTH": "8",
        "PASSWORD_REQUIRE_UPPER": "true",
        "PASSWORD_REQUIRE_DIGIT": "true",
        "PASSWORD_REQUIRE_SPECIAL": "true",
    }
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()

    # ska godkänna ett starkt lösenord
    policy.validate("StrongP@ssw0rd")

    # ska avvisa lösenord som inte uppfyller kraven
    with pytest.raises(Exception):
        policy.validate("weak")  # för kort, saknar krav

