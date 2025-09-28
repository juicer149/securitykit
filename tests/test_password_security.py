import pytest

from securitykit.services.password_security import PasswordSecurity
from securitykit.policies.password import PasswordPolicy
from securitykit.algorithms.argon2 import Argon2Policy
from securitykit.core.algorithm import Algorithm
from securitykit.exceptions import InvalidPolicyConfig


@pytest.fixture
def hasher():
    """Provide a simple Argon2 hasher for tests."""
    policy = Argon2Policy(time_cost=2, memory_cost=65536, parallelism=2)
    return Algorithm("argon2", policy)


@pytest.fixture
def security(hasher):
    """PasswordSecurity with default policy."""
    policy = PasswordPolicy(min_length=8)
    return PasswordSecurity(policy, hasher)


# ----------------------------
# Hash + verify roundtrip
# ----------------------------
def test_hash_and_verify(security):
    password = "StrongPass123!"
    hashed = security.hash(password)

    assert isinstance(hashed, str)
    assert security.verify(password, hashed)
    assert not security.verify("WrongPass", hashed)


# ----------------------------
# PasswordPolicy enforcement
# ----------------------------
def test_policy_too_short(security):
    with pytest.raises(InvalidPolicyConfig):
        security.hash("short")


def test_policy_missing_uppercase(security):
    with pytest.raises(InvalidPolicyConfig):
        security.hash("weakpassword123!")


def test_policy_missing_digit(security):
    with pytest.raises(InvalidPolicyConfig):
        security.hash("NoDigitsHere!")


def test_policy_missing_special(security):
    with pytest.raises(InvalidPolicyConfig):
        security.hash("NoSpecial123")


# ----------------------------
# Verify safe failure
# ----------------------------
def test_verify_returns_false_on_missing_inputs(security):
    assert not security.verify(None, None)
    assert not security.verify("", None)
    assert not security.verify("Password", None)


# ----------------------------
# Custom policy variations
# ----------------------------
def test_policy_with_relaxed_rules(hasher):
    policy = PasswordPolicy(
        min_length=4,
        require_upper=False,
        require_lower=False,
        require_digit=False,
        require_special=False,
    )
    security = PasswordSecurity(policy, hasher)

    # should pass because no requirements except length
    password = "abcd"
    hashed = security.hash(password)
    assert security.verify(password, hashed)
