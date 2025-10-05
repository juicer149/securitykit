import pytest

from securitykit.hashing.capabilities import CapabilityInfo
from securitykit.transform.pepper.factory import PepperFactory
from securitykit.transform.pepper.strategies import HmacStrategy


def _config(hmac_key="KeyForTests", mode="hmac"):
    # ConfigLoader enforces actual booleans for bool fields
    return {
        "PEPPER_ENABLED": True,
        "PEPPER_MODE": mode,
        "PEPPER_HMAC_KEY": hmac_key,
        "PEPPER_HMAC_ALGO": "sha256",
    }


def test_pepper_factory_uses_native_secret_for_argon2(monkeypatch):
    # Patch the late-bound registry symbol so PepperFactory sees it
    def fake_get_diag(_variant):
        return CapabilityInfo(available=True, version="21.3.0", extra={"supports_secret": True})
    monkeypatch.setattr("securitykit.hashing.registry.get_diagnostic", fake_get_diag)

    cfg = _config(hmac_key="SuperSecret")
    app = PepperFactory.from_config("argon2", cfg)

    assert app.prehash_pipeline is None
    assert app.algo_kwargs.get("secret") == b"SuperSecret"


def test_pepper_factory_hmac_prehash_for_bcrypt(monkeypatch):
    def fake_get_diag(_variant):
        return CapabilityInfo(available=True, version="4.1.0", extra={"supports_secret": False})
    monkeypatch.setattr("securitykit.hashing.registry.get_diagnostic", fake_get_diag)

    cfg = _config(hmac_key="AnotherSecret")
    app = PepperFactory.from_config("bcrypt", cfg)

    assert app.prehash_pipeline is not None
    assert app.algo_kwargs == {}

    pw = "Password123!"
    transformed = app.prehash_pipeline(pw)
    assert transformed != pw

    # HmacStrategy.key must be bytes
    strategy = HmacStrategy(key=b"AnotherSecret", algo="sha256")
    assert transformed == strategy.apply(pw)
