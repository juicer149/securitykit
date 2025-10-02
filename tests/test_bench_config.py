import pytest

from securitykit.bench.config import BenchmarkConfig
from securitykit.bench.exceptions import MissingBenchSchemaError
from securitykit.hashing.policy_registry import register_policy


def test_benchmark_config_success():
    cfg = BenchmarkConfig(variant="argon2", target_ms=123, tolerance=0.2, rounds=2)
    # Egenskaper satt & schema finns
    assert cfg.variant == "argon2"
    assert isinstance(cfg.schema, dict)
    assert len(cfg.schema) > 0
    assert cfg.policy_cls.__name__.lower().startswith("argon2")


def test_benchmark_config_missing_schema():
    # Registrera en policy utan BENCH_SCHEMA för att trigga felet
    @register_policy("noschema")  # type: ignore
    class NoSchemaPolicy:
        pass

    with pytest.raises(MissingBenchSchemaError):
        BenchmarkConfig(variant="noschema")
