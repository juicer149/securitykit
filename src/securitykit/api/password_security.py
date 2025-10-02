# securitykit/api/password_security.py
"""
High-level API for password security:
- Validate against password policy
- Hash passwords
- Verify hashes
- Rehash if outdated
"""

# api/password_security.py
import os
from securitykit.hashing.factory import HashingFactory
from securitykit.password.factory import PasswordFactory

# Load configuration once
_config = os.environ
_algo = HashingFactory(_config).get_algorithm()
_validator = PasswordFactory(_config).get_validator()


def hash_password(password: str) -> str:
    """Validate and hash a password."""
    _validator.validate(password)
    return _algo.hash(password)


def verify_password(password: str, stored_hash: str) -> bool:
    """Verify a password against a stored hash."""
    return _algo.verify(stored_hash, password)


def rehash_password(password: str, stored_hash: str) -> str:
    """Rehash if needed, otherwise return existing hash."""
    if _algo.needs_rehash(stored_hash):
        return hash_password(password)
    return stored_hash
