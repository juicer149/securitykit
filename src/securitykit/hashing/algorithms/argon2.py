# securitykit/hashing/algorithms/argon2.py
from typing import Optional
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.interfaces import AlgorithmProtocol
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.exceptions import HashingError, VerificationError
from securitykit.logging_config import logger


@register_algorithm("argon2")
class Argon2(AlgorithmProtocol):
    """Password hashing and verification with Argon2id."""

    def __init__(self, policy: Optional[Argon2Policy] = None) -> None:
        self.policy = policy or Argon2Policy()
        self._hasher = PasswordHasher(
            time_cost=self.policy.time_cost,
            memory_cost=self.policy.memory_cost,
            parallelism=self.policy.parallelism,
            hash_len=self.policy.hash_length,
            salt_len=self.policy.salt_length,
        )

    def hash(self, password: str) -> str:
        if not password:
            raise HashingError("Password cannot be empty")
        return self._hasher.hash(password)

    def verify(self, stored_hash: str | None, password: str | None) -> bool:
        if not stored_hash or not password:
            return False
        try:
            return self._hasher.verify(stored_hash, password)
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
