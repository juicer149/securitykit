from dataclasses import dataclass, field
from typing import Mapping
from securitykit.config import DEFAULTS
from securitykit.hashing.policy_registry import get_policy_class
from securitykit.hashing.interfaces import BenchValue
from securitykit.bench.exceptions import MissingBenchSchemaError

DEFAULT_TARGET_MS = 250
DEFAULT_TOLERANCE = 0.15
DEFAULT_ROUNDS = 5
DEFAULT_NEUTRAL_PEPPER: Mapping[str, str] = {"PEPPER_ENABLED": "false"}

@dataclass(frozen=True)
class BenchmarkConfig:
    variant: str = DEFAULTS["HASH_VARIANT"]
    target_ms: int = DEFAULT_TARGET_MS
    tolerance: float = DEFAULT_TOLERANCE
    rounds: int = DEFAULT_ROUNDS
    neutralize_pepper: bool = True  # new
    extra_config: Mapping[str, str] | None = None  # additional façade config

    policy_cls: type = field(init=False)
    schema: dict[str, list[BenchValue]] = field(init=False)

    def __post_init__(self):
        policy_cls = get_policy_class(self.variant)
        schema = getattr(policy_cls, "BENCH_SCHEMA", None)
        if not schema:
            raise MissingBenchSchemaError(
                f"Policy '{self.variant}' cannot be benchmarked (missing BENCH_SCHEMA)."
            )
        object.__setattr__(self, "policy_cls", policy_cls)
        object.__setattr__(self, "schema", schema)

    def algorithm_config(self) -> Mapping[str, str] | None:
        base = {}
        if self.neutralize_pepper:
            base.update(DEFAULT_NEUTRAL_PEPPER)
        if self.extra_config:
            base.update(self.extra_config)
        return base or None
