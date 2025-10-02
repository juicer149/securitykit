import os
import pytest
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader
from securitykit.exceptions import ConfigValidationError


@dataclass
class HashPolicy:
    time_cost: int
    parallelism: int = 1
    label: str = "baseline"


def test_loader_basic_build():
    cfg = {
        "HASH_TIME_COST": "4",
        "HASH_PARALLELISM": "2",
        "HASH_LABEL": "custom",
    }
    loader = ConfigLoader(cfg)
    policy = loader.build(HashPolicy, prefix="HASH_", name="HashPolicy")
    assert policy.time_cost == 4
    assert policy.parallelism == 2
    assert policy.label == "custom"


def test_loader_missing_required():
    loader = ConfigLoader({})
    with pytest.raises(ConfigValidationError):
        loader.build(HashPolicy, prefix="HASH_", name="HashPolicy")


def test_loader_from_env(monkeypatch):
    monkeypatch.setenv("HP_TIME_COST", "5")
    loader = ConfigLoader.from_env()
    policy = loader.build(HashPolicy, prefix="HP_", name="HashPolicy")
    assert policy.time_cost == 5
    assert policy.parallelism == 1
    assert policy.label == "baseline"


def test_numeric_not_boolean():
    cfg = {"HP_TIME_COST": "1"}  # Should be integer 1, not True
    loader = ConfigLoader(cfg)
    policy = loader.build(HashPolicy, prefix="HP_", name="HashPolicy")
    assert isinstance(policy.time_cost, int)
    assert policy.time_cost == 1


def test_size_suffix_and_list():
    @dataclass
    class Mix:
        mem: int
        tags: list[str]

    cfg = {
        "MIX_MEM": "64k",
        "MIX_TAGS": "alpha,beta,gamma",
    }
    loader = ConfigLoader(cfg)
    mix = loader.build(Mix, prefix="MIX_", name="Mix")
    assert mix.mem == 64 * 1024
    assert mix.tags == ["alpha", "beta", "gamma"]
