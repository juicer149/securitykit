# src/securitykit/services/password_security.py
"""
Password security service: combines policy enforcement and hashing.

This module provides the `PasswordSecurity` class, which serves as the
single entry point for password management in applications.

Doctest example:

    >>> from securitykit import Algorithm, Argon2Policy, PasswordPolicy
    >>> from securitykit.services.password_security import PasswordSecurity
    >>> policy = PasswordPolicy(min_length=12, require_upper=False, require_special=False)
    >>> algo = Algorithm("argon2", Argon2Policy())
    >>> service = PasswordSecurity(policy, algo)
    >>> hashed = service.hash("validpass1234")
    >>> service.verify("validpass1234", hashed)
    True
    >>> service.verify("wrongpass", hashed)
    False
    >>> service.needs_rehash(hashed) in (True, False)
    True

Notes:
    - Validation always runs before hashing.
    - Verification returns False for missing/invalid inputs.
    - Rehashing is handled transparently if algorithm parameters change.
"""

from typing import Optional
import os

from securitykit.core.algorithm import Algorithm
from securitykit.core.policy_registry import get_policy_class
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
        """
        Initialize PasswordSecurity.

        Args:
            policy (PasswordPolicy): Rules for password complexity.
            hasher (Algorithm): Algorithm wrapper (e.g. Argon2).
        """
        self.policy = policy
        self.hasher = hasher

    # -------------------
    # Validation
    # -------------------
    def validate(self, password: str) -> None:
        """
        Validate password strength against policy.

        Args:
            password (str): Plaintext password to validate.

        Raises:
            InvalidPolicyConfig: If the password violates policy requirements.
        """
        self.policy.validate(password)

    # -------------------
    # Hashing
    # -------------------
    def hash(self, password: str) -> str:
        """
        Validate and hash a password in one step.

        Args:
            password (str): Plaintext password.

        Returns:
            str: A securely hashed password string.

        Raises:
            InvalidPolicyConfig: If password does not meet policy.
        """
        self.validate(password)
        return self.hasher.hash(password)

    # -------------------
    # Verification
    # -------------------
    def verify(self, password: Optional[str], stored_hash: Optional[str]) -> bool:
        """
        Verify a password against a stored hash.

        Args:
            password (str | None): Plaintext password.
            stored_hash (str | None): Stored hash string.

        Returns:
            bool: True if verification succeeds, False otherwise.
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
        """
        Check if an existing hash should be rehashed.

        Args:
            hash_value (str): Stored hash.

        Returns:
            bool: True if rehashing is needed.
        """
        return self.hasher.needs_rehash(hash_value)

    def rehash(self, password: str, old_hash: str) -> str:
        """
        Conditionally rehash a password if old hash is outdated.

        Args:
            password (str): Plaintext password.
            old_hash (str): Existing stored hash.

        Returns:
            str: New hash if rehashed, otherwise the old hash.
        """
        if self.needs_rehash(old_hash):
            return self.hash(password)
        return old_hash

    # -------------------
    # Factory
    # -------------------
    @classmethod
    def from_env(cls) -> "PasswordSecurity":
        """
        Build a PasswordSecurity service from environment variables (.env/.env.local).
        """
        variant = os.getenv("HASH_VARIANT", "argon2").lower()
        policy_cls = get_policy_class(variant)

        kwargs = {}
        for field in getattr(policy_cls, "BENCH_SCHEMA", {}).keys():
            env_key = f"{variant.upper()}_{field.upper()}"
            value = os.getenv(env_key)
            if value is None:
                raise RuntimeError(f"Missing required env config: {env_key}")
            kwargs[field] = int(value)

        algo_policy = policy_cls(**kwargs)
        algo = Algorithm(variant, algo_policy)

        pwd_policy = PasswordPolicy(
            min_length=int(os.getenv("PASSWORD_MIN_LENGTH", 12)),
            require_upper=os.getenv("PASSWORD_REQUIRE_UPPER", "true").lower() in ("1", "true", "yes", "on"),
            require_lower=os.getenv("PASSWORD_REQUIRE_LOWER", "true").lower() in ("1", "true", "yes", "on"),
            require_digit=os.getenv("PASSWORD_REQUIRE_DIGIT", "true").lower() in ("1", "true", "yes", "on"),
            require_special=os.getenv("PASSWORD_REQUIRE_SPECIAL", "true").lower() in ("1", "true", "yes", "on"),
        )

        return cls(pwd_policy, algo)
