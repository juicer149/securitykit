import pytest
from dataclasses import dataclass
from securitykit.hashing import policy_registry
from securitykit.exceptions import UnknownPolicyError


def test_register_and_get_policy_class():
    policy_registry._policy_registry._registry.clear()

    @dataclass
    class DummyPolicy:
        foo: int = 1
        BENCH_SCHEMA = {}

    policy_registry.register_policy("dummy_policy")(DummyPolicy)
    cls = policy_registry.get_policy_class("dummy_policy")

    assert cls is DummyPolicy
    assert "dummy_policy" in policy_registry.list_policies()


def test_get_policy_class_unknown():
    policy_registry._policy_registry._registry.clear()
    with pytest.raises(UnknownPolicyError):
        policy_registry.get_policy_class("does_not_exist")
