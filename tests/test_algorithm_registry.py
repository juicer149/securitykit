import pytest
from securitykit.hashing import algorithm_registry
from securitykit.exceptions import UnknownAlgorithmError


def test_register_and_get_algorithm_class():
    # Nollställ registry innan testet
    algorithm_registry._algorithm_registry._registry.clear()

    class DummyAlgo:
        def __init__(self, *args, **kwargs): ...
        def hash(self, pw): return "HASH"
        def verify(self, h, pw): return True
        def needs_rehash(self, h): return False

    algorithm_registry.register_algorithm("dummy")(DummyAlgo)
    cls = algorithm_registry.get_algorithm_class("dummy")

    assert cls is DummyAlgo
    assert "dummy" in algorithm_registry.list_algorithms()


def test_get_algorithm_class_unknown():
    algorithm_registry._algorithm_registry._registry.clear()
    with pytest.raises(UnknownAlgorithmError):
        algorithm_registry.get_algorithm_class("nonexistent")
