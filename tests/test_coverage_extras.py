# tests/test_coverage_extras.py
import logging
import pytest

from securitykit.algorithms.argon2 import Argon2
from securitykit.policies.argon2 import Argon2Policy
from securitykit.core.algorithm import Algorithm
from securitykit.exceptions import HashingError, VerificationError


def test_argon2_hash_empty_password_raises():
    algo = Argon2(Argon2Policy())
    with pytest.raises(HashingError):
        algo.hash("")


def test_argon2_verify_returns_false_on_empty_inputs():
    algo = Argon2(Argon2Policy())
    assert algo.verify(None, "password") is False
    assert algo.verify("hash", None) is False
    assert algo.verify(None, None) is False
    assert algo.verify("", "") is False


def test_argon2_needs_rehash_false_on_empty():
    algo = Argon2(Argon2Policy())
    assert algo.needs_rehash("") is False
    assert algo.needs_rehash(None) is False


def test_argon2_needs_rehash_handles_exception(caplog):
    algo = Argon2(Argon2Policy())

    def boom(_):
        raise RuntimeError("fail")

    # Ersätt _hasher med dummy som kastar fel
    algo._hasher = type("DummyHasher", (), {"check_needs_rehash": boom})()

    caplog.set_level(logging.ERROR)
    result = algo.needs_rehash("irrelevant")
    assert result is False
    assert any("rehash check failed" in msg for msg in caplog.messages)


def test_algorithm_needs_rehash_without_impl_method():
    class DummyAlgo:
        def hash(self, pw): return "hash"
        def verify(self, h, pw): return True
        # saknar needs_rehash

    algo = Algorithm("argon2", Argon2Policy())  # skapar en giltig variant
    algo.impl = DummyAlgo()  # ersätt implementationen
    assert algo.needs_rehash("hash") is False


def test_algorithm_verify_raises_error():
    class BadAlgo:
        def hash(self, pw): return "hash"
        def verify(self, h, pw): raise RuntimeError("boom")
        def needs_rehash(self, h): return False

    algo = Algorithm("argon2", Argon2Policy())  # giltig variant
    algo.impl = BadAlgo()

    with pytest.raises(VerificationError):
        algo.verify("hash", "pw")

