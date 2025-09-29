# securitykit/bench/enumerator.py
import itertools
from typing import Any, Iterator, Mapping


class PolicyEnumerator:
    """Generate all possible policies from BENCH_SCHEMA."""

    def __init__(self, policy_cls: type, schema: Mapping[str, list[Any]]):
        self.policy_cls = policy_cls
        self.schema = schema

    def generate(self) -> Iterator[object]:
        """Yield all policy instances from schema combinations."""
        param_names = list(self.schema.keys())
        param_values = list(self.schema.values())
        for values in itertools.product(*param_values):
            params = dict(zip(param_names, values))
            yield self.policy_cls(**params)
