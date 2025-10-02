import pytest
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.policy_registry import register_policy


# Dynamiskt registrera en policy som kräver param som vi inte skickar
@register_policy("tempstrict")  # type: ignore
class TempStrictPolicy:
    def __init__(self, required_param: int):
        self.required_param = required_param


def test_hashing_factory_policy_build_failure(monkeypatch):
    # Ingen TEMPSTRICT_REQUIRED_PARAM i config => ConfigLoader ska kasta ConfigValidationError innan Algorithm skapas
    # Vi testar via get_policy, inte get_algorithm.
    from securitykit.exceptions import ConfigValidationError
    factory = HashingFactory({"HASH_VARIANT": "tempstrict"})
    with pytest.raises(ConfigValidationError):
        factory.get_policy("tempstrict")
