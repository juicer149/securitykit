import pytest

from securitykit.password.policy import PasswordPolicy
from securitykit.password.strength_evaluator import PasswordStrengthEvaluator
from securitykit.exceptions import InvalidPolicyConfig


def test_evaluator_summarize_and_levels():
    policy = PasswordPolicy(min_length=8, complexity_min_length=12, complexity_rule=3)
    ev = PasswordStrengthEvaluator(policy)

    # Weak: short and missing many classes
    out1 = ev.summarize("short")
    assert out1["fulfilled_rules"] <= 2
    assert out1["strength"] in {"Extremely Weak", "Very Weak", "Weak"}
    assert "min_length>=12" in out1["missing"]

    # Stronger: long enough and diverse
    out2 = ev.summarize("StrongPass123!")
    assert out2["fulfilled_rules"] >= 4
    assert out2["strength"] in {"Strong", "Very Strong"}
    assert isinstance(out2["mask"], int)


def test_complexity_rule_edge_validation_and_soft_threshold_warning(caplog):
    # invalid complexity_rule
    with pytest.raises(InvalidPolicyConfig):
        PasswordPolicy(min_length=8, complexity_rule=0)

    # invalid complexity_min_length
    with pytest.raises(InvalidPolicyConfig):
        PasswordPolicy(min_length=8, complexity_min_length=-1)

    # soft threshold less than hard min: allowed but should warn
    caplog.set_level("WARNING", logger="securitykit")
    _ = PasswordPolicy(min_length=12, complexity_min_length=8)
    assert any("soft rule is redundant" in r.message.lower() for r in caplog.records)


def test_describe_missing_and_count_bits():
    policy = PasswordPolicy(min_length=8, complexity_min_length=12)
    ev = PasswordStrengthEvaluator(policy)

    # Deliberately craft a password that meets only some rules
    out = ev.summarize("Onlylowercaseandlong")
    mask = out["mask"]
    fulfilled = ev.count_fulfilled(mask)
    missing = ev.describe_missing(mask)

    assert 1 <= fulfilled <= 4
    assert isinstance(missing, list)
