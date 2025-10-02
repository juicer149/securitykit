import pytest
from securitykit.password.policy import PasswordPolicy
from securitykit.exceptions import InvalidPolicyConfig


def test_policy_defaults_ok(caplog):
    policy = PasswordPolicy()
    assert policy.min_length == 8
    d = policy.to_dict()
    assert d["min_length"] == 8
    # Default min_length (8) < recommended (12) ⇒ warning
    assert any("below recommended minimum" in r.message for r in caplog.records)


def test_policy_custom_min_length_triggers_warning_low(caplog):
    caplog.clear()
    policy = PasswordPolicy(min_length=5)
    assert policy.min_length == 5
    assert any("below recommended minimum" in r.message for r in caplog.records)


def test_policy_custom_min_length_unusually_high_warning(caplog):
    caplog.clear()
    # > PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH (128)
    policy = PasswordPolicy(min_length=129)
    assert policy.min_length == 129
    assert any("unusually high" in r.message for r in caplog.records)


def test_policy_min_length_too_small_raises():
    with pytest.raises(InvalidPolicyConfig) as exc:
        PasswordPolicy(min_length=0)
    assert "at least" in str(exc.value)


def test_policy_min_length_too_large_raises():
    with pytest.raises(InvalidPolicyConfig) as exc:
        PasswordPolicy(min_length=PasswordPolicy.PASSWORD_MAX_LENGTH + 1)
    assert "must be <=" in str(exc.value)


def test_policy_to_dict_structure():
    policy = PasswordPolicy(min_length=14, require_upper=False)
    d = policy.to_dict()
    assert d["min_length"] == 14
    assert d["require_upper"] is False
    assert set(d.keys()) == {
        "min_length",
        "require_upper",
        "require_lower",
        "require_digit",
        "require_special",
    }
