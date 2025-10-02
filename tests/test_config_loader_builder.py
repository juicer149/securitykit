import pytest
from dataclasses import dataclass
from securitykit.utils.config_loader.sources import ValueSource
from securitykit.utils.config_loader.converters import ConverterRegistry
from securitykit.utils.config_loader.builder import PolicyBuilder
from securitykit.exceptions import ConfigValidationError


@dataclass
class DemoPolicy:
    time_cost: int
    memory_cost: int = 65536
    enabled: bool = True
    label: str = "DEF"


def test_policy_builder_success(caplog):
    src = ValueSource({"DEMO_TIME_COST": "3"})
    reg = ConverterRegistry()
    builder = PolicyBuilder(src, reg)
    policy = builder.build(DemoPolicy, prefix="DEMO_", label="DemoPolicy")
    assert policy.time_cost == 3
    assert policy.memory_cost == 65536
    assert policy.enabled is True
    assert policy.label == "DEF"
    # Ensure warning logged for defaults (3 optional fields)
    assert sum(1 for r in caplog.records if "Optional config" in r.message) == 3


def test_policy_builder_missing_required():
    src = ValueSource({})  # no DEMO_TIME_COST
    reg = ConverterRegistry()
    builder = PolicyBuilder(src, reg)
    with pytest.raises(ConfigValidationError) as exc:
        builder.build(DemoPolicy, prefix="DEMO_", label="DemoPolicy")
    assert "DEMO_TIME_COST" in str(exc.value)


def test_policy_builder_invalid_value_raises():
    # Provide something that will remain a non-int and then cause failure only if class enforces it.
    # dataclasses won't enforce types, so we simulate by custom __init__:

    class StrictPolicy:
        def __init__(self, count: int):
            if not isinstance(count, int):
                raise ValueError("count must be int")
            self.count = count

    src = ValueSource({"STRICT_COUNT": "abc"})  # default_parse => "abc"
    reg = ConverterRegistry()
    builder = PolicyBuilder(src, reg)
    with pytest.raises(ConfigValidationError) as exc:
        builder.build(StrictPolicy, prefix="STRICT_", label="StrictPolicy")
    assert "Invalid configuration for StrictPolicy" in str(exc.value)
