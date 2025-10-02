# tests/common/dummy_impls.py
from typing import Protocol, Optional

__all__ = ["AlgorithmLike", "DummyImpl", "NoRehash", "BadAlgo"]


class AlgorithmLike(Protocol):
    """
    Minimal protocol to mirror the interface of real Algorithm implementations.
    Used only for typing in test doubles.
    """

    def hash(self, password: str) -> str: ...
    def verify(self, stored_hash: str, password: str) -> bool: ...
    def needs_rehash(self, stored_hash: str) -> bool: ...


class DummyImpl:
    """
    Fake implementation of AlgorithmLike for testing.
    Can be configured to raise in specific methods via `raise_in`.
    """

    def __init__(self, policy=None, **kwargs):
        self.policy = policy
        self.raise_in: Optional[str] = None

    def hash(self, password: str) -> str:
        if self.raise_in == "hash":
            raise RuntimeError("hash failure")
        return f"HASHED:{password}"

    def verify(self, stored_hash: str, password: str) -> bool:
        if self.raise_in == "verify":
            raise RuntimeError("verify failure")
        return stored_hash == f"HASHED:{password}"

    def needs_rehash(self, stored_hash: str) -> bool:
        if self.raise_in == "needs_rehash":
            raise RuntimeError("rehash failure")
        return stored_hash.startswith("OLD:")


class NoRehash:
    """
    Fake implementation missing a real `needs_rehash` method.
    Always returns True from verify, hash is constant.
    """

    def __init__(self, *args, **kwargs):
        # Ignorera inkommande args (som policy)
        pass

    def hash(self, pw: str) -> str:
        return "X"

    def verify(self, h: str, pw: str) -> bool:
        return True

    # Note: intentionally missing needs_rehash()



class BadAlgo:
    """
    Fake implementation that raises in verify().
    """

    def hash(self, pw: str) -> str:
        return "hash"

    def verify(self, h: str, pw: str) -> bool:
        raise RuntimeError("boom")

    def needs_rehash(self, h: str) -> bool:
        return False
