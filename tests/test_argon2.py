import pytest
from securitykit.algorithms.argon2 import Argon2
from securitykit.policies.argon2 import Argon2Policy


def test_argon2_hash_and_verify():
    """
    Argon2 hashing and verification should work correctly.
    """
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    algo = Argon2(policy)

    password = "MySecureP@ssw0rd!"
    hash1 = algo.hash(password)
    assert isinstance(hash1, str)

    # Correct password should verify
    assert algo.verify(hash1, password)

    # Wrong password should not verify
    assert not algo.verify(hash1, "WrongPassword123")


def test_argon2_salt_uniqueness():
    """
    The same password should produce different hashes because of random salt.
    """
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    algo = Argon2(policy)

    password = "SamePassword"
    hash1 = algo.hash(password)
    hash2 = algo.hash(password)

    assert hash1 != hash2  # Different salt → different hashes
    assert algo.verify(hash1, password)
    assert algo.verify(hash2, password)


@pytest.mark.parametrize("password", ["a", "x" * 1000])
def test_argon2_edge_passwords(password):
    """
    Argon2 should handle both very short and very long passwords.
    """
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    algo = Argon2(policy)

    hash_value = algo.hash(password)
    assert algo.verify(hash_value, password)

