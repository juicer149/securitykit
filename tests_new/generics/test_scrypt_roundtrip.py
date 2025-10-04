from securitykit.hashing.factory import HashingFactory
from ..common.helpers import VALID_PASSWORD


def test_scrypt_roundtrip_and_needs_rehash():
    low_cfg = {
        "HASH_VARIANT": "scrypt",
        "SCRYPT_N": 2**13,  # lower to avoid OpenSSL memory cap on some setups
        "SCRYPT_R": 8,
        "SCRYPT_P": 1,
        "SCRYPT_SALT_LENGTH": 16,
        "SCRYPT_HASH_LENGTH": 32,
    }
    high_cfg = {
        "HASH_VARIANT": "scrypt",
        "SCRYPT_N": 2**14,  # increase cost within safe bounds
        "SCRYPT_R": 8,
        "SCRYPT_P": 1,
        "SCRYPT_SALT_LENGTH": 16,
        "SCRYPT_HASH_LENGTH": 32,
    }

    algo_low = HashingFactory(low_cfg).get_algorithm()
    h_low = algo_low.hash(VALID_PASSWORD)
    assert algo_low.verify(h_low, VALID_PASSWORD) is True

    algo_high = HashingFactory(high_cfg).get_algorithm()
    assert algo_high.verify(h_low, VALID_PASSWORD) is True
    assert algo_high.needs_rehash(h_low) is True

    h_new = algo_high.hash(VALID_PASSWORD)
    assert h_new != h_low
    assert algo_high.verify(h_new, VALID_PASSWORD) is True
    assert algo_high.needs_rehash(h_new) is False
