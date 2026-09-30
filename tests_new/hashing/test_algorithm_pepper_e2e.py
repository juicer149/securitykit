import importlib.util

import pytest

from securitykit.hashing.capabilities import CapabilityInfo
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.algorithm import Algorithm
from securitykit.bench.config import BenchmarkConfig


@pytest.mark.skipif(importlib.util.find_spec("bcrypt") is None, reason="bcrypt not installed")
def test_algorithm_bcrypt_hmac_prehash_e2e(monkeypatch):
    # Advertise no native secret support for bcrypt so PepperFactory uses HMAC prehash
    def fake_get_diag(_variant):
        return CapabilityInfo(available=True, version="4.1.0", extra={"supports_secret": False})
    monkeypatch.setattr("securitykit.hashing.registry.get_diagnostic", fake_get_diag)

    password = "Sufficiently$Strong1"
    cfg1 = {
        "HASH_VARIANT": "bcrypt",
        "BCRYPT_ROUNDS": 4,  # keep test fast
        "PEPPER_ENABLED": True,
        "PEPPER_MODE": "hmac",
        "PEPPER_HMAC_KEY": "PepperKey-One",
        "PEPPER_HMAC_ALGO": "sha256",
    }
    algo1 = HashingFactory(cfg1).get_algorithm()
    digest = algo1.hash(password)
    assert algo1.verify(digest, password) is True

    # Changing the HMAC key changes the prehash → verify should fail
    cfg2 = {
        "HASH_VARIANT": "bcrypt",
        "BCRYPT_ROUNDS": 4,
        "PEPPER_ENABLED": True,
        "PEPPER_MODE": "hmac",
        "PEPPER_HMAC_KEY": "PepperKey-Two",
        "PEPPER_HMAC_ALGO": "sha256",
    }
    algo2 = HashingFactory(cfg2).get_algorithm()
    assert algo2.verify(digest, password) is False


def test_algorithm_can_be_constructed_directly():
    algo = Algorithm("scrypt", config={"PEPPER_ENABLED": "false"})
    digest = algo.hash("pw")
    assert algo.verify(digest, "pw")


def test_benchmark_config_can_be_constructed_directly():
    assert BenchmarkConfig("argon2").policy_cls.__name__ == "Argon2Policy"
