import pytest
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader
from securitykit.exceptions import ConfigValidationError


def test_negative_and_float_preserved():
    @dataclass
    class P:
        delta: int
        ratio: float

    cfg = {
        "P_DELTA": "-7",
        "P_RATIO": "2.50",
    }
    loader = ConfigLoader(cfg)
    p = loader.build(P, prefix="P_", name="P")
    assert p.delta == -7
    assert abs(p.ratio - 2.50) < 1e-9


def test_semicolon_list():
    @dataclass
    class P:
        items: list[str]

    cfg = {"P_ITEMS": "a; b ;c"}
    loader = ConfigLoader(cfg)
    p = loader.build(P, prefix="P_", name="P")
    assert p.items == ["a", "b", "c"]


def test_multiple_missing_required_accumulate_in_message():
    @dataclass
    class Multi:
        a: int
        b: int
        c: int = 5

    loader = ConfigLoader({})
    with pytest.raises(ConfigValidationError) as exc:
        loader.build(Multi, prefix="MULTI_", name="Multi")
    msg = str(exc.value)
    assert "MULTI_A" in msg and "MULTI_B" in msg
    # MULTI_C should not appear (has default)


def test_invalid_post_init_validation():
    @dataclass
    class Strict:
        x: int

        def __post_init__(self):
            if self.x < 0:
                raise ValueError("x must be >= 0")

    cfg = {"STRICT_X": "-5"}
    loader = ConfigLoader(cfg)
    with pytest.raises(ConfigValidationError) as exc:
        loader.build(Strict, prefix="STRICT_", name="Strict")
    assert "Invalid configuration for Strict" in str(exc.value)
