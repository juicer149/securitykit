# tests/test_argon2.py
import pytest

from securitykit.hashing.algorithms.argon2 import Argon2
from securitykit.hashing.policies.argon2 import Argon2Policy


@pytest.fixture
def argon2_algo():
    """
    Fixture som returnerar en färdig Argon2-instans
    med en rimlig standardpolicy.
    """
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    return Argon2(policy)


def test_argon2_hash_and_verify(argon2_algo):
    password = "MySecureP@ssw0rd!"
    hash1 = argon2_algo.hash(password)
    assert isinstance(hash1, str)

    assert argon2_algo.verify(hash1, password)
    assert not argon2_algo.verify(hash1, "WrongPassword123")


def test_argon2_salt_uniqueness(argon2_algo):
    password = "SamePassword"
    hash1 = argon2_algo.hash(password)
    hash2 = argon2_algo.hash(password)

    # Hashes ska vara olika pga slumpmässigt salt
    assert hash1 != hash2

    # Men båda ska verifiera korrekt
    assert argon2_algo.verify(hash1, password)
    assert argon2_algo.verify(hash2, password)


@pytest.mark.parametrize("password", ["a", "x" * 1000])
def test_argon2_edge_passwords(argon2_algo, password):
    hash_value = argon2_algo.hash(password)
    assert argon2_algo.verify(hash_value, password)
