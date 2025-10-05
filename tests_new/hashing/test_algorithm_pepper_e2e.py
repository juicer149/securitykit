import inspect
import pytest

from securitykit.hashing.capabilities import CapabilityInfo
from securitykit.hashing.factory import HashingFactory


@pytest.mark.skipif("argon2" not in pytest.importorskip("pkgutil").iter_modules(), reason="argon2 not installed")
def test_algorithm_argon2_native_secret_e2e(monkeypatch):
    # Ensure argon2-cffi supports the 'secret' parameter, otherwise skip.
    a2 = pytest.importorskip("argon2")
    PasswordHasher = getattr(a2, "PasswordHasher")
    sig = inspect.signature(PasswordHasher)
    if "secret" not in sig.parameters:
        pytest.skip("argon2-cffi does not support PasswordHasher(secret=...) in this environment")

    # Advertise native secret support via diagnostics
    def fake_get_diag(_variant):
        return CapabilityInfo(available=True, version=getattr(a2, "__version__", "unknown"), extra={"supports_secret": True})
    monkeypatch.setattr("securitykit.hashing.registry.get_diagnostic", fake_get_diag)

    password = "CorrectHorseBatteryStaple!"
    cfg1 = {
        "HASH_VARIANT": "argon2",
        "PEPPER_ENABLED": True,
        "PEPPER_MODE": "hmac",
        "PEPPER_HMAC_KEY": "PepperKey-One",
    }
    algo1 = HashingFactory(cfg1).get_algorithm()
    digest = algo1.hash(password)
    assert algo1.verify(digest, password) is True

    # Change the pepper key: verification should now fail (different Argon2 secret)
    cfg2 = {
        "HASH_VARIANT": "argon2",
        "PEPPER_ENABLED": True,
        "PEPPER_MODE": "hmac",
        "PEPPER_HMAC_KEY": "PepperKey-Two",
    }
    algo2 = HashingFactory(cfg2).get_algorithm()
    assert algo2.verify(digest, password) is False


@pytest.mark.skipif("bcrypt" not in pytest.importorskip("pkgutil").iter_modules(), reason="bcrypt not installed")
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
