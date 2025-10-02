import pytest
from securitykit.hashing.algorithms.argon2 import Argon2
from securitykit.exceptions import HashingError


def test_empty_password_raises():
    algo = Argon2()
    with pytest.raises(HashingError):
        algo.hash("")


def test_verify_with_none_returns_false():
    algo = Argon2()
    assert algo.verify(None, "pw") is False
    assert algo.verify("hash", None) is False


def test_needs_rehash_handles_exception(caplog):
    algo = Argon2()

    class FakeHasher:
        def check_needs_rehash(self, _):
            raise RuntimeError("boom")

    algo._hasher = FakeHasher()
    caplog.set_level("ERROR")

    assert algo.needs_rehash("hash") is False
    assert any("rehash check failed" in rec.message for rec in caplog.records)
