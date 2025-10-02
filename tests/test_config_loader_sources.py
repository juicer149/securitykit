import pytest
from securitykit.utils.config_loader.sources import ValueSource


def test_value_source_basic():
    src = ValueSource({"A": "1", "B": "x"})
    assert src.has("A") is True
    assert src.has("Z") is False
    assert src.get("A") == "1"
    assert set(src.keys()) == {"A", "B"}
