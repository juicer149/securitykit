from __future__ import annotations
from typing import ClassVar

try:
    from argon2 import PasswordHasher  # type: ignore[import-not-found]
    from argon2.exceptions import VerifyMismatchError  # type: ignore[import-not-found]
except Exception as e:  # pragma: no cover
    raise RuntimeError("argon2-cffi is required for Argon2 hashing") from e

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.exceptions import HashingError, VerificationError
from securitykit.logging_config import logger


@register_algorithm("argon2")
class Argon2:
    """
    Argon2id implementation expecting *already peppered* password input
    for its raw methods. Pepper is applied by the Algorithm façade.
    """

    DEFAULT_POLICY_CLS: ClassVar[type[Argon2Policy]] = Argon2Policy

    def __init__(self, policy: Argon2Policy | None = None) -> None:
        policy = policy or Argon2Policy()
        if not isinstance(policy, Argon2Policy):
            raise TypeError("policy must be Argon2Policy")

        self.policy = policy
        self._hasher = PasswordHasher(
            time_cost=policy.time_cost,
            memory_cost=policy.memory_cost,
            parallelism=policy.parallelism,
            hash_len=policy.hash_length,
            salt_len=policy.salt_length,
        )

    # New raw API
    def hash_raw(self, peppered_password: str) -> str:
        if not peppered_password:
            raise HashingError("Password cannot be empty")
        return self._hasher.hash(peppered_password)

    def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
        if not stored_hash or not peppered_password:
            return False
        try:
            return self._hasher.verify(stored_hash, peppered_password)
        except VerifyMismatchError:
            return False
        except Exception as e:
            raise VerificationError(f"Argon2 verification failed: {e}") from e

    def needs_rehash(self, stored_hash: str) -> bool:
        if not stored_hash:
            return False
        try:
            return self._hasher.check_needs_rehash(stored_hash)
        except Exception as e:
            logger.error("Argon2 rehash check failed: %s", e)
            return False
