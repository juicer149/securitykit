import pytest
from securitykit.hashing import algorithm_registry
from securitykit.exceptions import HashingError
from ..common.helpers import build_algorithm


def test_reject_empty_password_on_hash(algorithm_name):
    """
    All algorithms should raise HashingError (or subclass) on empty password.
    """
    algo = build_algorithm(algorithm_name)
    with pytest.raises(HashingError):
        algo.hash("")


def test_invalid_policy_type_raises(algorithm_name):
    """
    Passing an object that is not the expected concrete policy should raise TypeError.
    """
    Algo = algorithm_registry.get_algorithm_class(algorithm_name)
    with pytest.raises(TypeError):
        Algo(object())  # type: ignore[arg-type]
