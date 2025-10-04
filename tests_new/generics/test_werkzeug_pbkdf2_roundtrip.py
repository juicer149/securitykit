import pytest

from securitykit.hashing.factory import HashingFactory
from ..common.helpers import VALID_PASSWORD


def test_werkzeug_pbkdf2_roundtrip_and_needs_rehash():
    try:
        low = {
            "HASH_VARIANT": "werkzeug_pbkdf2",
            "WERKZEUG_PBKDF2_METHOD": "pbkdf2:sha256",
            "WERKZEUG_PBKDF2_ITERATIONS": 150_000,  # lower
            "WERKZEUG_PBKDF2_SALT_LENGTH": 16,
        }
        high = {
            "HASH_VARIANT": "werkzeug_pbkdf2",
            "WERKZEUG_PBKDF2_METHOD": "pbkdf2:sha256",
            "WERKZEUG_PBKDF2_ITERATIONS": 260_000,  # higher
            "WERKZEUG_PBKDF2_SALT_LENGTH": 16,
        }

        algo_low = HashingFactory(low).get_algorithm()
        h_low = algo_low.hash(VALID_PASSWORD)
        assert algo_low.verify(h_low, VALID_PASSWORD) is True

        algo_high = HashingFactory(high).get_algorithm()
        assert algo_high.verify(h_low, VALID_PASSWORD) is True
        assert algo_high.needs_rehash(h_low) is True

        h_new = algo_high.hash(VALID_PASSWORD)
        assert h_new != h_low
        assert algo_high.verify(h_new, VALID_PASSWORD) is True
        assert algo_high.needs_rehash(h_new) is False

    except RuntimeError as e:
        if "Werkzeug is required" in str(e):
            pytest.skip("Werkzeug not installed")
        raise
