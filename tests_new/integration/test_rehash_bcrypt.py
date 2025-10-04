import pytest
from securitykit.hashing.factory import HashingFactory
from ..common.helpers import VALID_PASSWORD

def test_bcrypt_rehash_via_factory_mapping_when_rounds_increase():
    try:
        low_cfg = {"HASH_VARIANT": "bcrypt", "BCRYPT_ROUNDS": 10}
        high_cfg = {"HASH_VARIANT": "bcrypt", "BCRYPT_ROUNDS": 12}

        algo_low = HashingFactory(low_cfg).get_algorithm()
        h_low = algo_low.hash(VALID_PASSWORD)

        algo_high = HashingFactory(high_cfg).get_algorithm()
        assert algo_high.verify(h_low, VALID_PASSWORD) is True
        assert algo_high.needs_rehash(h_low) is True

        h_new = algo_high.hash(VALID_PASSWORD)
        assert h_new != h_low
        assert algo_high.verify(h_new, VALID_PASSWORD) is True
        assert algo_high.needs_rehash(h_new) is False
    except RuntimeError as e:
        # bcrypt lib not installed in this environment
        if "bcrypt library is required" in str(e):
            pytest.skip("bcrypt not installed")
        raise
