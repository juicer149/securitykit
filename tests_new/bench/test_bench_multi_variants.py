import pytest

from securitykit.bench.bench import run_benchmark
from securitykit.hashing import policy_registry


def _minimized_schema(schema: dict) -> dict:
    """
    Return a version of BENCH_SCHEMA with one (first) candidate per dimension to
    keep the cartesian space tiny for tests.
    """
    if not schema:
        return {}
    minimized = {}
    for k, values in schema.items():
        if isinstance(values, list) and values:
            minimized[k] = [values[0]]
    return minimized


def test_run_benchmark_smoke_all_variants(patch_algo_hash, patch_perf_counter, monkeypatch):
    """
    Iterate over all registered policies with a non-empty BENCH_SCHEMA,
    minimize their schema to a single combination and ensure run_benchmark succeeds.

    This covers multiple variants, not just argon2, without slow timing.
    """
    variants = policy_registry.list_policies()
    saw_any = False

    for variant in variants:
        Policy = policy_registry.get_policy_class(variant)
        schema = getattr(Policy, "BENCH_SCHEMA", {})
        if not schema:
            continue

        saw_any = True
        reduced = _minimized_schema(schema)
        # Patch that policy's BENCH_SCHEMA for the duration of this loop iteration
        monkeypatch.setattr(Policy, "BENCH_SCHEMA", reduced, raising=False)

        data = run_benchmark(variant, target_ms=50, tolerance=0.50, rounds=1)
        assert "best" in data and "best_result" in data
        best = data["best"]
        # Best env must at least include HASH_VARIANT and at least one policy key
        assert best.get("HASH_VARIANT") == variant
        assert any(k.startswith(variant.upper() + "_") for k in best)

    if not saw_any:
        pytest.skip("No benchmarkable policies (empty BENCH_SCHEMA across variants)")
