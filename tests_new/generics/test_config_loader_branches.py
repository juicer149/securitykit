import pytest
from dataclasses import dataclass

from securitykit.utils.config_loader import ConfigLoader, export_schema
from securitykit.exceptions import ConfigValidationError


@dataclass
class MixedPolicy:
    size: int = 1024
    enabled: bool = True
    tags: list[str] | None = None
    ratio: float = 1.5
    level: int | None = None


def test_config_loader_parsing_and_missing():
    cfg = {
        "MIXED_SIZE": "64k",
        "MIXED_ENABLED": "false",
        "MIXED_TAGS": "a,b;c",
        "MIXED_RATIO": "2.75",
        # level omitted -> None
    }
    loader = ConfigLoader(cfg)
    p = loader.build(MixedPolicy, prefix="MIXED_", name="mixed")
    assert p.size == 65536
    assert p.enabled is False
    assert p.tags == ["a", "b", "c"]
    assert p.ratio == 2.75
    assert p.level is None


def test_config_loader_invalid_and_required():
    @dataclass
    class Req:
        foo: int  # required
        bar: int = 7

    cfg = {"REQ_FOO": "not_int"}
    loader = ConfigLoader(cfg)
    with pytest.raises(ConfigValidationError) as e:
        loader.build(Req, prefix="REQ_", name="ReqPolicy")
    msg = str(e.value)
    # Acceptera både tidigare och nya formuleringar
    assert any(
        phrase in msg
        for phrase in [
            "Invalid value",          # tidigare konverteringsfel-path
            "invalid literal",        # ev. Python casting-meddelande
            "Type mismatch",          # ny typ-enforcement
        ]
    ), msg


def test_export_schema_lists_all():
    rows = export_schema(MixedPolicy, prefix="MIXED_")
    keys = {r["config_key"] for r in rows}
    assert {"MIXED_SIZE", "MIXED_LEVEL", "MIXED_RATIO"} <= keys
