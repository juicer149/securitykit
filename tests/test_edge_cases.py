import pytest
import logging

from securitykit.core.factory import SecurityFactory, ConfigValidationError
from securitykit.policies.argon2 import (
    Argon2Policy,
    ARGON2_MIN_MEMORY,
    ARGON2_RECOMMENDED_MEMORY,
    ARGON2_RECOMMENDED_PARALLELISM,
    ARGON2_RECOMMENDED_TIME_COST,
)
from securitykit.policies.password import PasswordPolicy
from securitykit.services.password_security import PasswordSecurity


def test_warns_if_memory_cost_below_recommended(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(memory_cost=ARGON2_MIN_MEMORY + 1)
    assert policy.memory_cost == ARGON2_MIN_MEMORY + 1
    assert any("memory_cost" in msg.lower() for msg in caplog.messages)


def test_warns_if_parallelism_below_recommended(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(parallelism=ARGON2_RECOMMENDED_PARALLELISM)
    assert policy.parallelism == ARGON2_RECOMMENDED_PARALLELISM
    assert any("parallelism" in msg.lower() for msg in caplog.messages)


def test_warns_if_time_cost_above_recommended(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(time_cost=ARGON2_RECOMMENDED_TIME_COST + 5)
    assert policy.time_cost == ARGON2_RECOMMENDED_TIME_COST + 5
    assert any("time_cost" in msg.lower() for msg in caplog.messages)


def test_warns_if_memory_cost_above_max(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(memory_cost=ARGON2_RECOMMENDED_MEMORY * 20)
    assert policy.memory_cost > ARGON2_RECOMMENDED_MEMORY
    assert any("extremely high" in msg.lower() for msg in caplog.messages)


def test_factory_invalid_config_raises():
    """Ogiltiga config-värden ska kasta ConfigValidationError."""
    config = {
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "not-a-number",
        "ARGON2_MEMORY_COST": ARGON2_MIN_MEMORY,
        "ARGON2_PARALLELISM": 2,
        "ARGON2_HASH_LENGTH": 32,
        "ARGON2_SALT_LENGTH": 16,
    }
    factory = SecurityFactory(config)
    with pytest.raises(ConfigValidationError):
        factory.get_algorithm()


def test_password_security_rehash_needed():
    """Simulerar ett rehash-scenario med dummy-algoritm."""
    policy = PasswordPolicy(min_length=8, require_upper=False, require_special=False)

    class DummyAlgo:
        def hash(self, pw): return "hash-" + pw
        def verify(self, h, pw): return h == "hash-" + pw
        def needs_rehash(self, h): return True

    ps = PasswordSecurity(policy, DummyAlgo())
    new_hash = ps.rehash("oldhash", "password123")
    assert new_hash == "hash-password123"
