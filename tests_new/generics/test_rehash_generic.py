import pytest

from securitykit.hashing import policy_registry
from ..common.helpers import VALID_PASSWORD, build_algorithm


def test_rehash_when_policy_parameter_increases(algorithm_name):
    """
    Deterministic rehash test:
      - Build a baseline policy/algo and hash a password.
      - Find any dimension in BENCH_SCHEMA where a larger candidate than the current exists.
      - Build a new policy with that increased dimension and a new algo.
      - Assert needs_rehash is True for the old hash under the new policy.
      - Rehash and validate properties of the new hash.
    """
    PolicyCls = policy_registry.get_policy_class(algorithm_name)
    schema = getattr(PolicyCls, "BENCH_SCHEMA", {})
    if not schema:
        pytest.skip("Policy has no BENCH_SCHEMA; cannot synthesize rehash scenario.")

    base_policy = PolicyCls()
    algo_low = build_algorithm(algorithm_name, base_policy)
    h1 = algo_low.hash(VALID_PASSWORD)

    # Find a dimension we can increase
    increase_dim = None
    increase_val = None
    for dim, candidates in schema.items():
        current = getattr(base_policy, dim, None)
        if isinstance(current, int):
            larger_candidates = sorted(v for v in candidates if isinstance(v, int) and v > current)
            if larger_candidates:
                increase_dim = dim
                increase_val = larger_candidates[0]  # pick the next higher candidate
                break

    if increase_dim is None:
        pytest.skip("No larger candidate value to trigger rehash scenario for any BENCH_SCHEMA dimension.")

    # Build the new (stricter) policy/algo
    new_policy_kwargs = {**base_policy.to_dict(), increase_dim: increase_val}
    strict_policy = PolicyCls(**new_policy_kwargs)
    algo_strict = build_algorithm(algorithm_name, strict_policy)

    # Old hash should verify but require rehash under the stricter policy
    assert algo_strict.verify(h1, VALID_PASSWORD) is True
    needs = algo_strict.needs_rehash(h1)
    assert needs is True, f"Expected needs_rehash=True when increasing {increase_dim} to {increase_val}"

    # Perform rehash and validate
    h2 = algo_strict.hash(VALID_PASSWORD)
    assert h2 != h1
    assert algo_strict.verify(h2, VALID_PASSWORD) is True
    assert algo_strict.needs_rehash(h2) is False
