import pytest

from securitykit.hashing.factory import HashingFactory
from ..common.helpers import VALID_PASSWORD


def test_rehash_via_factory_mapping_increase(algorithm_name):
    """
    Integration-style: ensure needs_rehash triggers when we increase a relevant policy dimension
    using typed mapping configs (avoids env caching).

    Covers: argon2, bcrypt, scrypt, werkzeug_pbkdf2 (skips if a variant is not registered).
    """
    if algorithm_name == "argon2":
        low_cfg = {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": 2,
            "ARGON2_MEMORY_COST": 65536,
            "ARGON2_PARALLELISM": 1,
        }
        high_cfg = {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": 4,
            "ARGON2_MEMORY_COST": 131072,
            "ARGON2_PARALLELISM": 2,
        }
    elif algorithm_name == "bcrypt":
        low_cfg = {"HASH_VARIANT": "bcrypt", "BCRYPT_ROUNDS": 10}
        high_cfg = {"HASH_VARIANT": "bcrypt", "BCRYPT_ROUNDS": 12}
    elif algorithm_name == "scrypt":
        # Keep within CI-friendly bounds; our implementation sets generous maxmem internally.
        low_cfg = {
            "HASH_VARIANT": "scrypt",
            "SCRYPT_N": 2**13,
            "SCRYPT_R": 8,
            "SCRYPT_P": 1,
            "SCRYPT_SALT_LENGTH": 16,
            "SCRYPT_HASH_LENGTH": 32,
        }
        high_cfg = {
            "HASH_VARIANT": "scrypt",
            "SCRYPT_N": 2**14,  # increase cost
            "SCRYPT_R": 8,
            "SCRYPT_P": 1,
            "SCRYPT_SALT_LENGTH": 16,
            "SCRYPT_HASH_LENGTH": 32,
        }
    elif algorithm_name == "werkzeug_pbkdf2":
        try:
            import werkzeug  # noqa: F401
        except Exception:
            pytest.skip("Werkzeug not installed/registered")
        low_cfg = {
            "HASH_VARIANT": "werkzeug_pbkdf2",
            "WERKZEUG_PBKDF2_METHOD": "pbkdf2:sha256",
            "WERKZEUG_PBKDF2_ITERATIONS": 150_000,
            "WERKZEUG_PBKDF2_SALT_LENGTH": 16,
        }
        high_cfg = {
            "HASH_VARIANT": "werkzeug_pbkdf2",
            "WERKZEUG_PBKDF2_METHOD": "pbkdf2:sha256",
            "WERKZEUG_PBKDF2_ITERATIONS": 260_000,
            "WERKZEUG_PBKDF2_SALT_LENGTH": 16,
        }
    else:
        pytest.skip(f"No integration mapping test for algorithm={algorithm_name}")

    algo_low = HashingFactory(low_cfg).get_algorithm()
    h_low = algo_low.hash(VALID_PASSWORD)

    algo_high = HashingFactory(high_cfg).get_algorithm()
    assert algo_high.verify(h_low, VALID_PASSWORD) is True
    assert algo_high.needs_rehash(h_low) is True

    h_new = algo_high.hash(VALID_PASSWORD)
    assert h_new != h_low
    assert algo_high.verify(h_new, VALID_PASSWORD) is True
    assert algo_high.needs_rehash(h_new) is False
