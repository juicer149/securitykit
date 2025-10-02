# tests/test_argon2_policy.py
import pytest

from securitykit.hashing.policies.argon2 import (
    Argon2Policy,
    ARGON2_MIN_TIME_COST,
    ARGON2_MIN_MEMORY,
    ARGON2_MIN_PARALLELISM,
    ARGON2_MIN_HASH_LENGTH,
    ARGON2_MIN_SALT_LENGTH,
    ARGON2_RECOMMENDED_TIME_COST,
    ARGON2_RECOMMENDED_MEMORY,
    ARGON2_RECOMMENDED_PARALLELISM,
    ARGON2_RECOMMENDED_HASH_LENGTH,
    ARGON2_MAX_TIME_COST,
    ARGON2_MAX_MEMORY,
    ARGON2_MAX_PARALLELISM,
)
from securitykit.exceptions import InvalidPolicyConfig


def test_policy_to_dict_roundtrip():
    policy = Argon2Policy(time_cost=3, memory_cost=65536, parallelism=2, hash_length=32, salt_length=16)
    d = policy.to_dict()
    assert d["time_cost"] == 3
    assert d["memory_cost"] == 65536
    assert d["parallelism"] == 2
    assert d["hash_length"] == 32
    assert d["salt_length"] == 16


@pytest.mark.parametrize(
    "kwargs, expected_message",
    [
        ({"time_cost": 0}, f"time_cost must be >= {ARGON2_MIN_TIME_COST}"),
        ({"memory_cost": 1024}, f"memory_cost must be >= {ARGON2_MIN_MEMORY}"),
        ({"parallelism": 0}, f"parallelism must be >= {ARGON2_MIN_PARALLELISM}"),
        ({"hash_length": 8}, f"hash_length must be >= {ARGON2_MIN_HASH_LENGTH}"),
        ({"salt_length": 8}, f"salt_length must be >= {ARGON2_MIN_SALT_LENGTH}"),
    ],
)
def test_policy_invalid_minimums_raise(kwargs, expected_message):
    with pytest.raises(InvalidPolicyConfig) as exc:
        Argon2Policy(**kwargs)
    assert expected_message in str(exc.value)


def test_policy_warns_when_below_recommended(caplog):
    # Force multiple warnings at once
    with caplog.at_level("WARNING"):
        Argon2Policy(
            time_cost=ARGON2_RECOMMENDED_TIME_COST - 1,
            memory_cost=ARGON2_RECOMMENDED_MEMORY - 1,
            parallelism=ARGON2_RECOMMENDED_PARALLELISM,  # "at or below"
            hash_length=ARGON2_RECOMMENDED_HASH_LENGTH - 1,
            salt_length=ARGON2_MIN_SALT_LENGTH,
        )
    msgs = [rec.message for rec in caplog.records]
    assert any("time_cost" in m for m in msgs)
    assert any("memory_cost" in m for m in msgs)
    assert any("parallelism" in m for m in msgs)
    assert any("hash_length" in m for m in msgs)


def test_policy_warns_when_above_max(caplog):
    with caplog.at_level("WARNING"):
        Argon2Policy(
            time_cost=ARGON2_MAX_TIME_COST + 1,
            memory_cost=ARGON2_MAX_MEMORY + 1,
            parallelism=ARGON2_MAX_PARALLELISM + 1,
        )
    msgs = [rec.message for rec in caplog.records]
    assert any("time_cost" in m for m in msgs)
    assert any("memory_cost" in m for m in msgs)
    assert any("parallelism" in m for m in msgs)
