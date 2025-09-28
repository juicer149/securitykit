import pytest

from securitykit.core.factory import SecurityFactory, BOOL_MAP
from securitykit.policies.password import PasswordPolicy


@pytest.mark.parametrize("raw,expected", list(BOOL_MAP.items()))
def test_factory_converts_bool_variants(raw, expected):
    """
    Ensure all keys in BOOL_MAP convert correctly to True/False
    when building a PasswordPolicy via SecurityFactory.
    """
    config = {
        "PASSWORD_SECURITY": "true",  # must be enabled
        "PASSWORD_MIN_LENGTH": 12,
        "PASSWORD_REQUIRE_UPPER": raw,
        "PASSWORD_REQUIRE_LOWER": raw,
        "PASSWORD_REQUIRE_DIGIT": raw,
        "PASSWORD_REQUIRE_SPECIAL": raw,
    }
    factory = SecurityFactory(config)
    policy = factory.get_password_policy()

    assert isinstance(policy, PasswordPolicy)
    assert policy.require_upper == expected
    assert policy.require_lower == expected
    assert policy.require_digit == expected
    assert policy.require_special == expected

