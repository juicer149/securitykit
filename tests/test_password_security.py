import pytest
import logging

from securitykit.core.algorithm import Algorithm
from securitykit.policies.argon2 import Argon2Policy
from securitykit.policies.password import PasswordPolicy
from securitykit.services.password_security import PasswordSecurity


def test_password_security_integration():
    """End-to-end test: PasswordPolicy + Algorithm should hash and verify correctly."""
    policy = PasswordPolicy(min_length=8, require_upper=False, require_special=False)
    algo = Algorithm("argon2", Argon2Policy(), pepper=None)
    service = PasswordSecurity(policy, algo)

    password = "validpass123"  # >=8, has lower + digit
    hashed = service.hash(password)

    # Should verify successfully
    assert service.verify(password, hashed) is True


def test_password_security_rehash_triggers(monkeypatch):
    """Rehash should return a new hash when needs_rehash is True."""
    policy = PasswordPolicy(min_length=8, require_upper=False, require_special=False)
    algo = Algorithm("argon2", Argon2Policy())
    service = PasswordSecurity(policy, algo)

    password = "valid1234"  # >=8, has digit
    hashed = service.hash(password)

    # Force needs_rehash to always return True
    monkeypatch.setattr(algo.impl, "needs_rehash", lambda _: True)

    new_hash = service.rehash(password, hashed)  # ✅ fixed order
    assert new_hash != hashed
    assert service.verify(password, new_hash)
