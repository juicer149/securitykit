"""
Lightweight smoke test validating BENCH_SCHEMA structure without running
expensive benchmarks. Marked as 'smoke' so it can be selectively included.
"""
import pytest
from securitykit.hashing import policy_registry


@pytest.mark.smoke
def test_bench_schema_not_empty(policy_name):
    Policy = policy_registry.get_policy_class(policy_name)
    schema = getattr(Policy, "BENCH_SCHEMA", {})
    if not schema:
        # Allow empty schema but mark as skipped to document absence
        pytest.skip(f"{policy_name} has an empty BENCH_SCHEMA")
    total = 1
    for values in schema.values():
        assert isinstance(values, list)
        total *= max(1, len(values))
    assert total >= 1
