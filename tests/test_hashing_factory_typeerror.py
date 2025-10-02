import pytest
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.policy_registry import register_policy
from securitykit.exceptions import ConfigValidationError

@register_policy("typeerrorpolicy")  # type: ignore
class TypeErrorPolicy:
    def __init__(self, value: int):
        # Force a TypeError if value is not passed (ConfigLoader will raise earlier),
        # but we also raise explicitly to test factory's except.
        raise TypeError("forced type error in policy constructor")

def test_hashing_factory_policy_constructor_typeerror():
    factory = HashingFactory({"HASH_VARIANT": "typeerrorpolicy"})
    with pytest.raises(ConfigValidationError):
        factory.get_policy("typeerrorpolicy")
