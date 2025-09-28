import logging
from securitykit.policies.argon2 import (
    Argon2Policy,
    ARGON2_MIN_MEMORY,
    ARGON2_RECOMMENDED_MEMORY,
    ARGON2_RECOMMENDED_PARALLELISM,
    ARGON2_RECOMMENDED_TIME_COST,
)


def test_warns_if_memory_cost_below_recommended(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(memory_cost=ARGON2_MIN_MEMORY + 1)  # giltig men under rekommenderad
    assert policy.memory_cost == ARGON2_MIN_MEMORY + 1
    assert any("memory_cost" in msg.lower() for msg in caplog.messages)


def test_warns_if_parallelism_below_recommended(caplog):
    caplog.set_level(logging.WARNING, logger="securitykit")
    policy = Argon2Policy(parallelism=ARGON2_RECOMMENDED_PARALLELISM)  # baseline
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
