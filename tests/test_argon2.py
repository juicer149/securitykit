import pytest
from securitykit.algorithms.argon2 import Argon2
from securitykit.policies.argon2 import Argon2Policy


@pytest.mark.parametrize("pepper", [None, "supersecretpepper"])
def test_argon2_hash_and_verify(pepper):
    """Hash och verify ska fungera både med och utan pepper."""
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    algo = Argon2(policy, pepper=pepper)

    password = "MySecureP@ssw0rd!"
    hash1 = algo.hash(password)
    assert isinstance(hash1, str)

    # Rätt lösenord ska verifiera
    assert algo.verify(hash1, password)

    # Fel lösenord ska inte verifiera
    assert not algo.verify(hash1, "WrongPassword123")


def test_argon2_salt_uniqueness():
    """Samma lösenord ska ge olika hashvärden p.g.a. slumpmässig salt."""
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

    assert hash1 != hash2  # salt ger olika hash
    assert algo.verify(hash1, password)
    assert algo.verify(hash2, password)


@pytest.mark.parametrize("password", ["a", "x" * 1000])
def test_argon2_edge_passwords(password):
    """Klarar både väldigt korta och väldigt långa lösenord."""
    policy = Argon2Policy(
        time_cost=2,
        memory_cost=65536,
        parallelism=2,
        hash_length=32,
        salt_length=16,
    )
    algo = Argon2(policy, pepper="edgepepper")

    hash_value = algo.hash(password)
    assert algo.verify(hash_value, password)

