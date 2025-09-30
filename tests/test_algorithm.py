import pytest
from securitykit.core.algorithm import Algorithm
from securitykit.exceptions import HashingError, VerificationError


class DummyImpl:
    """Minimal fake AlgorithmProtocol implementation for testing."""

    def __init__(self, policy=None, **kwargs):
        self.policy = policy
        self.raise_in = None  # which method to raise in

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


def test_with_pepper_and_without(monkeypatch):
    # Patch registry so Algorithm always returns DummyImpl
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda variant: DummyImpl)

    algo = Algorithm("argon2", pepper="PEP")
    assert algo._with_pepper("pw") == "pwPEP"

    algo_nopep = Algorithm("argon2")
    assert algo_nopep._with_pepper("pw") == "pw"  # branch without pepper


def test_hash_success_and_failure(monkeypatch):
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: DummyImpl)

    # Success
    algo = Algorithm("argon2")
    assert algo.hash("pw") == "HASHED:pw"

    # Failure path raises HashingError
    failing_impl = DummyImpl()
    failing_impl.raise_in = "hash"
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: lambda *a, **k: failing_impl)

    algo_fail = Algorithm("argon2")
    with pytest.raises(HashingError):
        algo_fail.hash("pw")


def test_verify_success_and_failure(monkeypatch):
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: DummyImpl)

    algo = Algorithm("argon2")
    hashed = algo.hash("pw")
    assert algo.verify(hashed, "pw") is True
    assert algo.verify(hashed, "wrong") is False

    # Force failure path
    failing_impl = DummyImpl()
    failing_impl.raise_in = "verify"
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: lambda *a, **k: failing_impl)

    algo_fail = Algorithm("argon2")
    with pytest.raises(VerificationError):
        algo_fail.verify("X", "pw")


def test_needs_rehash_success_and_failure(monkeypatch, caplog):
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: DummyImpl)

    algo = Algorithm("argon2")
    assert algo.needs_rehash("OLD:123") is True
    assert algo.needs_rehash("HASHED:123") is False

    # Impl without needs_rehash method → returns False
    class NoRehash:
        def __init__(self, *a, **kw): pass
        def hash(self, pw): return "X"
        def verify(self, h, pw): return True

    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: NoRehash)
    algo2 = Algorithm("argon2")
    assert algo2.needs_rehash("anything") is False

    # Impl that raises in needs_rehash
    failing_impl = DummyImpl()
    failing_impl.raise_in = "needs_rehash"
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: lambda *a, **k: failing_impl)

    algo_fail = Algorithm("argon2")
    caplog.set_level("ERROR")
    assert algo_fail.needs_rehash("X") is False
    assert any("Needs_rehash failed" in rec.message for rec in caplog.records)


def test_get_policy_dict_with_and_without_policy(monkeypatch):
    class Policy:
        def to_dict(self): return {"foo": 123}

    class Impl(DummyImpl):
        def __init__(self, policy=None, **kwargs):
            super().__init__(policy)

    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: Impl)

    # With policy
    algo = Algorithm("argon2", policy=Policy())
    d = algo.get_policy_dict()
    assert d == {"foo": 123}

    # Without policy
    algo2 = Algorithm("argon2")
    d2 = algo2.get_policy_dict()
    assert d2 == {}

def test_algorithm_callable(monkeypatch):
    monkeypatch.setattr("securitykit.core.algorithm.get_algorithm_class", lambda v: DummyImpl)

    algo = Algorithm("argon2")
    # __call__ ska vara samma som .hash()
    assert algo("pw") == algo.hash("pw")
    assert algo("pw") == "HASHED:pw"

