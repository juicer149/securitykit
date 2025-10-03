import pytest
from securitykit.hashing import algorithm_registry
from ..common.helpers import VALID_PASSWORD, build_algorithm
from ..common.parsers import parse_argon2, parse_bcrypt


def test_hash_parameter_encoding_matches_policy(algorithm_name):
    """
    For recognized algorithms:
      - Argon2: parse memory/time/parallelism and compare to policy
      - Bcrypt: parse cost rounds and compare to policy
    For unknown algorithms: ensure hash is non-empty (placeholder).
    """
    algo = build_algorithm(algorithm_name)
    h = algo.hash(VALID_PASSWORD)

    if algorithm_name == "argon2":
        parsed = parse_argon2(h)
        assert parsed is not None, "Invalid Argon2 hash format"
        policy = algo.policy
        assert parsed["time_cost"] == policy.time_cost
        assert parsed["memory_cost"] == policy.memory_cost
        assert parsed["parallelism"] == policy.parallelism

    elif algorithm_name == "bcrypt":
        parsed = parse_bcrypt(h)
        assert parsed is not None, "Invalid bcrypt hash format"
        policy = algo.policy
        assert parsed["rounds"] == policy.rounds
    else:
        assert h
