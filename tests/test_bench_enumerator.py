from securitykit.bench.enumerator import PolicyEnumerator
from securitykit.hashing.policy_registry import get_policy_class


def test_policy_enumerator_generate():
    Policy = get_policy_class("argon2")
    schema = {
        "time_cost": [2, 3],
        "memory_cost": [65536],
    }
    enum = PolicyEnumerator(Policy, schema)
    generated = list(enum.generate())
    # 2 * 1 = 2 kombinationer
    assert len(generated) == 2
    values = {p.time_cost for p in generated}  # type: ignore
    assert values == {2, 3}
