import pytest
from securitykit.hashing.algorithms.argon2 import Argon2
from securitykit.exceptions import VerificationError
from securitykit.hashing.policies.argon2 import Argon2Policy


def test_argon2_verify_invalid_hash_raises_verification_error():
    algo = Argon2(Argon2Policy())
    # Create a syntactically invalid hash (argon2 lib should raise a non-VerifyMismatch exception)
    bad_hash = "$argon2id$v=19$m=65536,t=2,p=1$INVALID$INVALID"
    with pytest.raises(VerificationError):
        algo.verify(bad_hash, "pw")


def test_argon2_needs_rehash_empty_string_short_circuits_false():
    algo = Argon2(Argon2Policy())
    assert algo.needs_rehash("") is False
