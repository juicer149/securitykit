from typing import Optional

from securitykit.core.algorithm import Algorithm
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import InvalidPolicyConfig, VerificationError
from securitykit.logging_config import logger


class PasswordSecurity:
    """
    High-level API for password management.

    - Enforces password policy (length, upper/lower/digit/special).
    - Handles hashing & verification with the configured algorithm.
    - One entry point for apps (e.g., Flask/ FastAPI).

    Typical usage:
        security = PasswordSecurity(policy, hasher)
        hash = security.hash("StrongPass123!")
        assert security.verify("StrongPass123!", hash)
    """

    def __init__(self, policy: PasswordPolicy, hasher: Algorithm) -> None:
        self.policy = policy
        self.hasher = hasher

    # -------------------
    # Validation only
    # -------------------
    def validate(self, password: str) -> None:
        """Validate password strength according to policy."""
        self.policy.validate(password)

    # -------------------
    # Hashing
    # -------------------
    def hash(self, password: str) -> str:
        """
        Validate + hash password in one step.
        Raises InvalidPolicyConfig if password does not meet policy.
        """
        self.validate(password)
        return self.hasher.hash(password)

    # -------------------
    # Verification
    # -------------------
    def verify(self, password: Optional[str], stored_hash: Optional[str]) -> bool:
        """
        Verify a password against a stored hash.

        Returns False if inputs are missing or invalid.
        Raises VerificationError if underlying algorithm fails unexpectedly.
        """
        if not password or not stored_hash:
            return False

        try:
            return self.hasher.verify(stored_hash, password)
        except VerificationError as e:
            logger.error("Password verification error: %s", e)
            return False

    # -------------------
    # Rehashing
    # -------------------
    def needs_rehash(self, hash_value: str) -> bool:
        """Check if an existing hash needs to be rehashed (e.g. parameters changed)."""
        return self.hasher.needs_rehash(hash_value)

    def rehash(self, hash_value: str, password: str) -> str:
        """If rehashing is needed, return new hash, otherwise return the same."""
        if self.needs_rehash(hash_value):
            return self.hash(password)
        return hash_value
