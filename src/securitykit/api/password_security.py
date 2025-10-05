"""
High-level API for password security:
- Validate against password policy
- Hash passwords
- Verify hashes
- Rehash if outdated
- Optional pre-database gate filtering

Pepper handling is configuration-driven (PEPPER_* keys)
and applied inside the Algorithm façade.
"""

from __future__ import annotations
import os
from typing import Mapping, Any

from securitykit.hashing.factory import HashingFactory
from securitykit.password.factory import PasswordFactory
from securitykit.password.gate import PasswordGate
from securitykit.exceptions import PasswordValidationError
from securitykit.logging_config import logger

_config: Mapping[str, Any] = os.environ
_algo = HashingFactory(_config).get_algorithm()
_validator = PasswordFactory(_config).get_validator()
_gate = PasswordGate(_validator.policy)  # Same policy, unified source of truth

# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _truthy(val: Any) -> bool:
    if isinstance(val, bool):
        return val
    if val is None:
        return False
    return str(val).strip().lower() in {"1", "true", "yes", "on"}

def _gate_precheck_or_raise(password: str) -> None:
    """Fast reject before heavy hashing (policy-consistent gate)."""
    if not _gate.allow(password):
        logger.debug("PasswordGate rejected password (precheck failed).")
        raise PasswordValidationError("Password rejected by PasswordGate (too weak or invalid).")

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def hash_password(password: str) -> str:
    """Validate (Gate + Policy) and hash a password."""
    _gate_precheck_or_raise(password)
    _validator.validate(password)
    return _algo.hash(password)

def verify_password(password: str, stored_hash: str) -> bool:
    """
    Verify a password against a stored hash.

    Note:
    - By default, PasswordGate is NOT applied here to avoid blocking legitimate
      logins with legacy/weak but existing passwords.
    - To apply the gate also on verify, set PASSWORD_GATE_ON_VERIFY=true.
    """
    if _truthy(_config.get("PASSWORD_GATE_ON_VERIFY", False)):
        if not _gate.allow(password):
            return False
    return _algo.verify(stored_hash, password)

def rehash_password(password: str, stored_hash: str) -> str:
    """Rehash if current parameters differ from stored hash requirements."""
    if _algo.needs_rehash(stored_hash):
        return hash_password(password)
    return stored_hash

def reload_configuration(new_mapping: Mapping[str, Any] | None = None) -> None:
    """
    Refresh internal singletons (used in tests or hot-reload scenarios).
    """
    global _config, _algo, _validator, _gate
    _config = new_mapping or os.environ
    _algo = HashingFactory(_config).get_algorithm()
    _validator = PasswordFactory(_config).get_validator()
    _gate = PasswordGate(_validator.policy)
