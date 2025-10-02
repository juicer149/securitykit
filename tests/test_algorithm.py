# tests/test_algorithm.py
import pytest

from securitykit.hashing.algorithm import Algorithm
from securitykit.exceptions import HashingError, VerificationError

from common.dummy_impls import DummyImpl, NoRehash, BadAlgo, AlgorithmLike


def test_with_pepper_and_without(monkeypatch):
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda variant: DummyImpl,  # type: ignore[return-value]
    )

    algo = Algorithm("argon2", pepper="PEP")
    assert algo._with_pepper("pw") == "pwPEP"

    algo_nopep = Algorithm("argon2")
    assert algo_nopep._with_pepper("pw") == "pw"  # branch without pepper


def test_hash_success_and_failure(monkeypatch):
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: DummyImpl,  # type: ignore[return-value]
    )

    # Success case
    algo = Algorithm("argon2")
    assert algo.hash("pw") == "HASHED:pw"

    # Failure case
    failing_impl: AlgorithmLike = DummyImpl()
    failing_impl.raise_in = "hash"  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: lambda *a, **k: failing_impl,
    )

    algo_fail = Algorithm("argon2")
    with pytest.raises(HashingError):
        algo_fail.hash("pw")


def test_verify_success_and_failure(monkeypatch):
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: DummyImpl,  # type: ignore[return-value]
    )

    algo = Algorithm("argon2")
    hashed = algo.hash("pw")
    assert algo.verify(hashed, "pw") is True
    assert algo.verify(hashed, "wrong") is False

    # Force failure path
    failing_impl: AlgorithmLike = DummyImpl()
    failing_impl.raise_in = "verify"  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: lambda *a, **k: failing_impl,
    )

    algo_fail = Algorithm("argon2")
    with pytest.raises(VerificationError):
        algo_fail.verify("X", "pw")


def test_needs_rehash_success_and_failure(monkeypatch, caplog):
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: DummyImpl,  # type: ignore[return-value]
    )

    algo = Algorithm("argon2")
    assert algo.needs_rehash("OLD:123") is True
    assert algo.needs_rehash("HASHED:123") is False

    # Impl without needs_rehash method
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: NoRehash,
    )
    algo2 = Algorithm("argon2")
    assert algo2.needs_rehash("anything") is False

    # Impl that raises in needs_rehash
    failing_impl: AlgorithmLike = DummyImpl()
    failing_impl.raise_in = "needs_rehash"  # type: ignore[attr-defined]
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: lambda *a, **k: failing_impl,
    )

    algo_fail = Algorithm("argon2")
    caplog.set_level("ERROR")
    assert algo_fail.needs_rehash("X") is False
    assert any("Needs_rehash failed" in rec.message for rec in caplog.records)


def test_get_policy_dict_with_and_without_policy(monkeypatch):
    class Policy:
        def to_dict(self):
            return {"foo": 123}

    class Impl(DummyImpl):
        def __init__(self, policy=None, **kwargs):
            super().__init__(policy)

    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: Impl,
    )

    # With policy
    algo = Algorithm("argon2", policy=Policy())
    d = algo.get_policy_dict()
    assert d == {"foo": 123}

    # Without policy
    algo2 = Algorithm("argon2")
    d2 = algo2.get_policy_dict()
    assert d2 == {}


def test_algorithm_callable(monkeypatch):
    monkeypatch.setattr(
        "securitykit.hashing.algorithm.get_algorithm_class",
        lambda v: DummyImpl,  # type: ignore[return-value]
    )

    algo = Algorithm("argon2")
    # __call__ should equal .hash()
    assert algo("pw") == algo.hash("pw")
    assert algo("pw") == "HASHED:pw"
