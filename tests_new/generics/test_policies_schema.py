import pytest
from securitykit.hashing import policy_registry
from securitykit.hashing.interfaces import PolicyProtocol


def test_policy_to_dict_and_schema(policy_name):
    """
    Validate fundamental policy features for every registered policy:
      - to_dict exists and returns a dict
      - BENCH_SCHEMA present and is a dict
      - All BENCH_SCHEMA values are lists
    """
    Policy = policy_registry.get_policy_class(policy_name)
    p = Policy()
    d = p.to_dict()
    assert isinstance(d, dict)
    schema = getattr(p, "BENCH_SCHEMA")
    assert isinstance(schema, dict)
    for k, v in schema.items():
        assert isinstance(k, str)
        assert isinstance(v, list)


def test_policy_structural_protocol(policy_name):
    """
    Structural typing check: concrete policy instances should satisfy PolicyProtocol.
    """
    Policy = policy_registry.get_policy_class(policy_name)
    p = Policy()
    assert isinstance(p, PolicyProtocol)
