import pytest

from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing import algorithm_registry, policy_registry
from securitykit.exceptions import (
    UnknownAlgorithmError,
    UnknownPolicyError,
    RegistryConflictError,
    HashingError,
    VerificationError,
)


def test_algorithm_delegate_hash_exception(monkeypatch):
    # Replace the implementation's hash_raw to throw -> catch in façade.
    algo = Algorithm("argon2")
    impl = algo.impl

    def boom(_pw: str):
        raise RuntimeError("fail")
    impl.hash_raw = boom  # type: ignore[attr-defined]

    with pytest.raises(HashingError):
        algo.hash("Secret123!")


def test_algorithm_delegate_verify_exception(monkeypatch):
    algo = Algorithm("argon2")
    impl = algo.impl

    def vboom(_stored: str, _pw: str):
        raise RuntimeError("verify fail")
    impl.verify_raw = vboom  # type: ignore[attr-defined]

    with pytest.raises(VerificationError):
        algo.verify("dummy", "Secret123!")


def test_algorithm_hash_empty_raises():
    algo = Algorithm("argon2")
    with pytest.raises(HashingError):
        algo.hash("")


def test_registry_unknown_algorithm():
    with pytest.raises(UnknownAlgorithmError):
        algorithm_registry.get_algorithm_class("nope123")


def test_registry_unknown_policy():
    with pytest.raises(UnknownPolicyError):
        policy_registry.get_policy_class("nope456")


def test_registry_duplicate_algorithm(monkeypatch):
    # Register a temporary class and try again to trigger duplicate.
    from securitykit.hashing.algorithm_registry import register_algorithm

    @register_algorithm("tempdup")
    class TempAlgo:
        def __init__(self, policy=None): pass
        def hash_raw(self, p: str): return p
        def verify_raw(self, h: str, p: str): return True

    with pytest.raises(RegistryConflictError):
        @register_algorithm("tempdup")
        class TempAlgo2:
            pass  # pragma: no cover

    # policy duplicate
    from securitykit.hashing.policy_registry import register_policy
    @register_policy("temppol")
    class TP:
        def __init__(self): pass
        def to_dict(self): return {}

    with pytest.raises(RegistryConflictError):
        @register_policy("temppol")
        class TP2:
            pass  # pragma: no cover
