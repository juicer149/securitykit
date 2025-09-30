# securitykit/services/password_security.py
import os
from typing import Optional

from securitykit.core.algorithm import Algorithm
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import InvalidPolicyConfig, VerificationError
from securitykit.logging_config import logger


class PasswordSecurity:
    """
    High-level API for password management.

    Responsibilities:
        - Enforces password policy (length, complexity).
        - Handles hashing & verification with the chosen algorithm.
        - Supports rehashing when algorithm parameters are updated.
    """

    def __init__(self, policy: PasswordPolicy, hasher: Algorithm) -> None:
        self.policy = policy
        self.hasher = hasher

    def validate(self, password: str) -> None:
        self.policy.validate(password)

    def hash(self, password: str) -> str:
        self.validate(password)
        return self.hasher.hash(password)

    def verify(self, password: Optional[str], stored_hash: Optional[str]) -> bool:
        if not password or not stored_hash:
            return False
        try:
            return self.hasher.verify(stored_hash, password)
        except VerificationError as e:
            logger.error("Password verification error: %s", e)
            return False

    def needs_rehash(self, hash_value: str) -> bool:
        return self.hasher.needs_rehash(hash_value)

    def rehash(self, password: str, old_hash: str) -> str:
        if self.needs_rehash(old_hash):
            return self.hash(password)
        return old_hash

    @classmethod
    def from_env(cls) -> "PasswordSecurity":
        """
        Build a PasswordSecurity service from environment variables (.env/.env.local).
        """
        from securitykit.core.factory import SecurityFactory
        factory = SecurityFactory(os.environ)
        return factory.get_password_security()
