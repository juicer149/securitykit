from __future__ import annotations
from typing import Any, Mapping

from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing import policy_registry

VALID_PASSWORD = "Aa1!abcd!"
INVALID_PASSWORDS = ["", " ", "\t", "\n"]


def build_algorithm(
    algorithm_name: str,
    policy: Any | None = None,
    config: Mapping[str, Any] | None = None,
    **kwargs: Any,
) -> Algorithm:
    """
    Construct and return the high-level Algorithm façade.

    Pepper handling, hashing & verification pathways are centralized in the façade.
    Concrete implementation classes expose hash_raw / verify_raw only.
    """
    return Algorithm(algorithm_name, policy=policy, config=config, **kwargs)


def build_lightweight_policy(variant: str):
    """
    Build a minimized-cost policy derived from BENCH_SCHEMA (if present)
    to keep tests fast. Chooses the smallest integer from each dimension that
    exists in the schema.

    Falls back to the default policy if schema missing or unusable.
    """
    PolicyCls = policy_registry.get_policy_class(variant)
    policy = PolicyCls()

    schema = getattr(PolicyCls, "BENCH_SCHEMA", None)
    if not schema:
        return policy

    overrides: dict[str, Any] = {}
    try:
        # Use to_dict() if available to start from existing values
        base_dict = policy.to_dict() if hasattr(policy, "to_dict") else {}
        for field, values in schema.items():
            ints = [v for v in values if isinstance(v, int)]
            if ints:
                overrides[field] = min(ints)
        if overrides:
            merged = {**base_dict, **overrides}
            return PolicyCls(**merged)
    except Exception:
        return policy

    return policy
