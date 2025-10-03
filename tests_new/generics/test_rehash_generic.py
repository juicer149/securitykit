import pytest
from securitykit.hashing import algorithm_registry, policy_registry
from ..common.helpers import VALID_PASSWORD, build_algorithm


def test_rehash_when_policy_parameter_increases(algorithm_name):
    """
    Heuristic rehash test:
      - Take the first policy dimension from BENCH_SCHEMA.
      - Increase it if possible.
      - Check needs_rehash result (True or False).
      - If True, hash again and ensure new hash differs & verifies.
    """
    PolicyCls = policy_registry.get_policy_class(algorithm_name)
    schema = getattr(PolicyCls, "BENCH_SCHEMA", {})
    if not schema:
        pytest.skip("Policy has no BENCH_SCHEMA; cannot synthesize rehash scenario.")

    base_policy = PolicyCls()
    algo1 = build_algorithm(algorithm_name, base_policy)
    h1 = algo1.hash(VALID_PASSWORD)

    dim, candidates = next(iter(schema.items()))
    current = getattr(base_policy, dim, None)
    larger = None
    if isinstance(current, int):
        for v in sorted([c for c in candidates if isinstance(c, int)]):
            if v > current:
                larger = v
                break
    if larger is None:
        pytest.skip("No larger candidate value to trigger rehash scenario.")

    new_policy_kwargs = {**base_policy.to_dict(), dim: larger}
    new_policy = PolicyCls(**new_policy_kwargs)
    algo2 = build_algorithm(algorithm_name, new_policy)

    needs = algo2.needs_rehash(h1)
    if needs:
        h2 = algo2.hash(VALID_PASSWORD)
        assert h2 != h1
        assert algo2.verify(h2, VALID_PASSWORD) is True
