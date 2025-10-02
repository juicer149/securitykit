import os
import importlib
import re
import pytest

from securitykit.exceptions import InvalidPolicyConfig


# -----------------------------
# Helper utilities for the tests
# -----------------------------

def _set_env(monkeypatch, mapping: dict[str, str]):
    """
    Reset all HASH_/ARGON2_/PASSWORD_ related variables then apply mapping.
    This prevents cross‑test contamination of module globals in password_security.
    """
    for k in list(os.environ.keys()):
        if k.startswith(("HASH_", "ARGON2_", "PASSWORD_")):
            monkeypatch.delenv(k, raising=False)
    for k, v in mapping.items():
        monkeypatch.setenv(k, v)


def _reload_password_security():
    """
    Force a reload so that password_security re-instantiates its module-level
    _algo and _validator objects based on current environment.
    """
    import securitykit.api.password_security as ps
    importlib.reload(ps)
    return ps


# -----------------------------
# Tests
# -----------------------------

def test_hash_and_verify_success(monkeypatch):
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
            "PASSWORD_REQUIRE_UPPER": "true",
            "PASSWORD_REQUIRE_LOWER": "true",
            "PASSWORD_REQUIRE_DIGIT": "true",
            "PASSWORD_REQUIRE_SPECIAL": "true",
        },
    )
    ps = _reload_password_security()

    password = "Aa1!abcd"
    hashed = ps.hash_password(password)
    assert isinstance(hashed, str)
    # Accept either "$argon2" or "$argon2id" form depending on backend
    assert "$argon2" in hashed

    assert ps.verify_password(password, hashed) is True
    assert ps.verify_password("WrongPass1!", hashed) is False


def test_hash_password_invalid_password_raises(monkeypatch):
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "10",
            "PASSWORD_REQUIRE_UPPER": "true",
            "PASSWORD_REQUIRE_LOWER": "true",
            "PASSWORD_REQUIRE_DIGIT": "true",
            "PASSWORD_REQUIRE_SPECIAL": "true",
        },
    )
    ps = _reload_password_security()

    with pytest.raises(InvalidPolicyConfig):
        ps.hash_password("loweronly")  # Missing all required classes


def test_rehash_password_no_change(monkeypatch):
    """
    If parameters are unchanged, rehash_password should return the original hash.
    """
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps = _reload_password_security()
    pwd = "Aa1!abcd"
    old_hash = ps.hash_password(pwd)

    new_hash = ps.rehash_password(pwd, old_hash)
    assert new_hash == old_hash


def test_rehash_password_triggers_on_time_cost_increase(monkeypatch):
    """
    Step 1: produce hash with time_cost=2
    Step 2: increase time_cost=3
    Step 3: rehash_password should produce a different hash
    """
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps1 = _reload_password_security()
    pwd = "Aa1!abcd"
    old_hash = ps1.hash_password(pwd)
    assert "$argon2" in old_hash

    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "3",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps2 = _reload_password_security()
    assert ps2._algo.needs_rehash(old_hash) is True

    new_hash = ps2.rehash_password(pwd, old_hash)
    assert new_hash != old_hash
    assert "$argon2" in new_hash
    assert ps2.verify_password(pwd, new_hash) is True


def test_rehash_password_returns_same_if_empty_hash(monkeypatch):
    """
    An empty stored hash should short‑circuit (needs_rehash False / validation False),
    and we return it unchanged.
    """
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps = _reload_password_security()
    empty_hash = ""
    pwd = "Aa1!abcd"
    res = ps.rehash_password(pwd, empty_hash)
    assert res == empty_hash
    assert ps.verify_password(pwd, empty_hash) is False


def test_rehash_password_corrupted_hash_may_rehash_or_not(monkeypatch):
    """
    A syntactically 'corrupted' hash (invalid salt/base64 parts) can lead Argon2
    to decide parameters mismatch → rehash OR treat it unreachable and return unchanged.
    Accept both behaviors to stay robust.
    """
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps = _reload_password_security()
    pwd = "Aa1!abcd"

    bad_hash = "$argon2id$v=19$m=65536,t=2,p=1$invalid$invalid"
    res = ps.rehash_password(pwd, bad_hash)

    if res == bad_hash:
        # No rehash -> must fail verification
        assert ps.verify_password(pwd, bad_hash) is False
    else:
        # Rehash occurred
        assert res != bad_hash
        assert "$argon2" in res
        assert ps.verify_password(pwd, res) is True


def test_verify_password_false_for_wrong_password(monkeypatch):
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "2",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps = _reload_password_security()
    pwd = "Aa1!abcd"
    h = ps.hash_password(pwd)
    assert ps.verify_password("Different1!", h) is False


def test_hash_format_contains_time_cost(monkeypatch):
    """
    Check that the hash encodes the configured time_cost (simple regex check).
    """
    _set_env(
        monkeypatch,
        {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": "3",
            "PASSWORD_MIN_LENGTH": "8",
        },
    )
    ps = _reload_password_security()
    h = ps.hash_password("Aa1!abcd")
    # Argon2 encoded parameters include t=3 (example)
    assert re.search(r"t=3", h), f"Expected time_cost t=3 in hash: {h}"
