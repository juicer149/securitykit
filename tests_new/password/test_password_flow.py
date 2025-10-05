import pytest

from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator
from securitykit.password.gate import PasswordGate
from securitykit.exceptions import PasswordValidationError


def test_password_validator_positive_and_negative():
    policy = PasswordPolicy(min_length=10, complexity_rule=3)
    v = PasswordValidator(policy)

    good = "StrongPass1!"
    v.validate(good)  # should not raise

    with pytest.raises(PasswordValidationError):
        v.validate("short")  # too short

    with pytest.raises(PasswordValidationError):
        v.validate("alllowercaseandlongenough")  # missing required digit/special/upper


def test_password_gate_allow_and_reject_reason():
    policy = PasswordPolicy(min_length=12, complexity_rule=3)
    gate = PasswordGate(policy)

    ok = "ValidPass123!"
    weak = "weakpass"

    assert gate.allow(ok) is True
    assert gate.allow(weak) is False

    reason = gate.reject_reason(weak)
    assert reason["allowed"] is False
    assert "complexity<" in ",".join(reason["reasons"]) or "min_length" in ",".join(reason["reasons"])
    assert isinstance(reason["fulfilled"], int)
    assert isinstance(reason["missing"], list)


def test_strength_label_and_feedback():
    policy = PasswordPolicy(min_length=8, complexity_rule=3)
    v = PasswordValidator(policy)

    pw = "Moderate1!"
    label = v.strength_label(pw)
    fb = v.feedback(pw)

    assert label in {"Moderate", "Strong", "Very Strong"}
    assert "Password strength:" in fb["message"]
    assert "missing" in fb
