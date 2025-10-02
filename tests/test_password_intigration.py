"""
High-level integration tests tying together:
  - Factory
  - Policy
  - Validator
"""

import pytest
from securitykit.password.factory import PasswordFactory
from securitykit.exceptions import InvalidPolicyConfig


def test_password_integration_happy_path():
    cfg = {
        "PASSWORD_MIN_LENGTH": "12",
        "PASSWORD_REQUIRE_UPPER": "true",
        "PASSWORD_REQUIRE_LOWER": "true",
        "PASSWORD_REQUIRE_DIGIT": "true",
        "PASSWORD_REQUIRE_SPECIAL": "true",
    }
    factory = PasswordFactory(cfg)
    validator = factory.get_validator()
    validator.validate("Aa1!abcdefgh")  # 12 chars, satisfies all


def test_password_integration_failure_case():
    cfg = {
        "PASSWORD_MIN_LENGTH": "12",
        "PASSWORD_REQUIRE_UPPER": "true",
        "PASSWORD_REQUIRE_LOWER": "true",
        "PASSWORD_REQUIRE_DIGIT": "true",
        "PASSWORD_REQUIRE_SPECIAL": "true",
    }
    factory = PasswordFactory(cfg)
    validator = factory.get_validator()
    with pytest.raises(InvalidPolicyConfig):
        validator.validate("aaaaaaaaaaaa")  # missing everything


def test_password_toggle_disable_complexity():
    cfg = {
        "PASSWORD_MIN_LENGTH": "5",
        "PASSWORD_REQUIRE_UPPER": "false",
        "PASSWORD_REQUIRE_LOWER": "false",
        "PASSWORD_REQUIRE_DIGIT": "false",
        "PASSWORD_REQUIRE_SPECIAL": "false",
    }
    factory = PasswordFactory(cfg)
    validator = factory.get_validator()
    validator.validate("abcde")  # Simple password passes (length only)
