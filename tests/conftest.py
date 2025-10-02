# tests/conftest.py
import os
import pytest
from securitykit.hashing.registry import load_all


@pytest.fixture(autouse=True, scope="session")
def load_algorithms_and_policies_once():
    """
    Load algorithms & policies at the beginning of the test session.
    """
    from securitykit.hashing import algorithm_registry, policy_registry
    load_all(force=True)
    print("AFTER RELOAD: algorithms =", algorithm_registry.list_algorithms())
    print("AFTER RELOAD: policies =", policy_registry.list_policies())


@pytest.fixture(autouse=True)
def reload_registry_each_test():
    """
    Force reload of registry before *each test* to guarantee consistency.
    """
    load_all(force=True)


@pytest.fixture(autouse=True)
def restore_env_each_test():
    """
    Ensure each test starts with a clean environment.
    Uses defaults from securitykit.config if needed.
    """
    old_env = os.environ.copy()
    yield
    os.environ.clear()
    os.environ.update(old_env)
