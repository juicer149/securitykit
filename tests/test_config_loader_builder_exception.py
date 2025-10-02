import pytest
from securitykit.utils.config_loader import ConfigLoader
from securitykit.exceptions import ConfigValidationError

class ExplodingPolicy:
    def __init__(self, a: int = 1):
        raise ValueError("boom")

def test_builder_instantiation_exception():
    loader = ConfigLoader({})
    with pytest.raises(ConfigValidationError) as exc:
        loader.build(ExplodingPolicy, prefix="EXP_", name="ExplodingPolicy")
    assert "Invalid configuration for ExplodingPolicy" in str(exc.value)
