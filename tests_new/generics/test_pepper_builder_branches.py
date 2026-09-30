import pytest
from securitykit.transform.pepper import apply_pepper, list_strategies
from securitykit.transform.pepper.builder import build_pepper_strategy
from securitykit.transform.pepper.model import PepperConfig
from securitykit.exceptions import PepperConfigError, UnknownPepperStrategyError, PepperStrategyConstructionError


def test_pepper_unknown_mode_fails_closed():
    with pytest.raises(UnknownPepperStrategyError):
        apply_pepper("secret", {"PEPPER_MODE": "doesnotexist"})


def test_pepper_interleave_freq_zero():
    with pytest.raises(PepperConfigError):
        apply_pepper(
            "abcd",
            {"PEPPER_MODE": "interleave", "PEPPER_INTERLEAVE_FREQ": "0", "PEPPER_SECRET": "X"},
        )


def test_decoration_modes_warn_that_they_are_not_cryptographic(caplog):
    out = apply_pepper("pw", {"PEPPER_MODE": "prefix", "PEPPER_SECRET": "^"})
    assert out == "^pw"
    assert any("not cryptographic" in r.message for r in caplog.records)


def test_pepper_hmac_missing_key_raises():
    with pytest.raises(PepperConfigError):
        build_pepper_strategy(PepperConfig(mode="hmac", hmac_key=""))


def test_pepper_hmac_short_key_warning(caplog):
    apply_pepper("pw", {"PEPPER_MODE": "hmac", "PEPPER_HMAC_KEY": "short"})
    assert any("short" in r.message.lower() for r in caplog.records)


def test_pepper_unsupported_hmac_algo():
    # Force unsupported algo
    with pytest.raises(PepperStrategyConstructionError):
        build_pepper_strategy(PepperConfig(mode="hmac", hmac_key="abcdefgh", hmac_algo="noalgo123"))


def test_pepper_lazy_list_strategies():
    # Should return at least built-ins even if not previously imported explicitly
    names = list_strategies()
    for n in ("noop", "suffix", "hmac"):
        assert n in names


@pytest.mark.parametrize("mode", ["prefix", "suffix", "prefix_suffix", "interleave"])
def test_decoration_mode_without_value_fails_closed(mode):
    with pytest.raises(PepperConfigError):
        apply_pepper("abcd", {"PEPPER_MODE": mode, "PEPPER_INTERLEAVE_FREQ": "2"})
