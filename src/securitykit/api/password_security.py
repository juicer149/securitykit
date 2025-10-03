"""
High-level API for password security:
- Validate against password policy
- Hash passwords
- Verify hashes
- Rehash if outdated

Pepper handling is configuration-driven (PEPPER_* keys) and applied
inside the Algorithm façade; this module does not manipulate pepper directly.
"""
from __future__ import annotations

import os
from typing import Mapping, Any

from securitykit.hashing.factory import HashingFactory
from securitykit.password.factory import PasswordFactory

_config: Mapping[str, Any] = os.environ
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
    """Rehash if current parameters differ from the stored hash requirements."""
    if _algo.needs_rehash(stored_hash):
        return hash_password(password)
    return stored_hash


def reload_configuration(new_mapping: Mapping[str, Any] | None = None) -> None:
    """
    Refresh internal singletons (used in tests or hot-reload scenarios).

    new_mapping:
        Optional new configuration mapping. If None, os.environ is re-read.

    Side-effects:
        Rebuilds algorithm + validator from scratch.
    """
    global _config, _algo, _validator
    _config = new_mapping or os.environ
    _algo = HashingFactory(_config).get_algorithm()
    _validator = PasswordFactory(_config).get_validator()
