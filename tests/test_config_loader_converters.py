import pytest
from securitykit.utils.config_loader.converters import (
    ConverterRegistry,
    default_parse,
)


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("true", True),
        ("True", True),
        ("on", True),
        ("yes", True),
        ("false", False),
        ("off", False),
        ("no", False),
        ("1", 1),          # IMPORTANT: NOT True
        ("0", 0),          # NOT False
        ("-5", -5),
        ("42", 42),
        ("3.14", 3.14),
        (" 64k ", 64 * 1024),
        ("8K", 8 * 1024),
        ("1M", 1024 * 1024),
        ("2g", 2 * 1024 * 1024 * 1024),
        ("a,b,c", ["a", "b", "c"]),
        ("x; y ;z", ["x", "y", "z"]),
        ("plain", "plain"),
    ],
)
def test_default_parse(raw, expected):
    assert default_parse(raw) == expected


def test_converter_registry_order():
    calls = []

    def c1(v):
        calls.append("c1")
        if isinstance(v, str):
            return v + "!"
        return v

    def c2(v):
        calls.append("c2")
        return v.upper() if isinstance(v, str) else v

    reg = ConverterRegistry()
    # front => runs first
    reg.register_front(c1)
    # back => runs last
    reg.register_back(c2)

    out = reg.convert("abc")
    # Chain: c1 -> default_parse -> c2
    assert calls[0] == "c1"
    assert calls[-1] == "c2"
    # c1 adds "!", default_parse leaves str as-is, c2 uppercases
    assert out == "ABC!"
