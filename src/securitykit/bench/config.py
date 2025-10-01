from dataclasses import dataclass, field
from securitykit.config import DEFAULTS
from securitykit.core.policy_registry import get_policy_class
from securitykit.core.interfaces import BenchValue
from securitykit.bench.exceptions import MissingBenchSchemaError

# Bench-specific defaults
DEFAULT_TARGET_MS = 250
DEFAULT_TOLERANCE = 0.15
DEFAULT_ROUNDS = 5


@dataclass(frozen=True)
class BenchmarkConfig:
    variant: str = DEFAULTS["HASH_VARIANT"]
    target_ms: int = DEFAULT_TARGET_MS
    tolerance: float = DEFAULT_TOLERANCE
    rounds: int = DEFAULT_ROUNDS

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
