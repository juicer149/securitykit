import pytest
from securitykit.hashing import algorithm_registry
from ..common.helpers import VALID_PASSWORD, build_algorithm


def test_roundtrip_default_policy(algorithm_name):
    """
    Basic roundtrip:
      - hash returns non-empty string
      - verify succeeds on original
      - verify fails on modified password
      - needs_rehash returns a boolean
    """
    algo = build_algorithm(algorithm_name)
    h = algo.hash(VALID_PASSWORD)
    assert isinstance(h, str) and h
    assert algo.verify(h, VALID_PASSWORD) is True
    assert algo.verify(h, VALID_PASSWORD + "X") is False
    assert isinstance(algo.needs_rehash(h), bool)

def test_roundtrip_with_custom_policy_argon2():
    from securitykit.hashing import policy_registry
    from securitykit.hashing.algorithm import Algorithm
    Policy = policy_registry.get_policy_class("argon2")
    custom = Policy(time_cost=1)
    a = Algorithm("argon2", policy=custom)
    h = a.hash(VALID_PASSWORD)
    assert a.verify(h, VALID_PASSWORD)
