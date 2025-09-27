# securitykit/algorithms/argon2.py
import logging
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError

from securitykit.core.algorithm_registry import register_algorithm
from securitykit.core.interfaces import AlgorithmProtocol
from securitykit.policies.argon2 import Argon2Policy
from securitykit.exceptions import HashingError, VerificationError

logger = logging.getLogger(__name__)


@register_algorithm("argon2")
class Argon2(AlgorithmProtocol):
    """Password hashing and verification with Argon2id."""

    def __init__(self, policy: Argon2Policy | None = None) -> None:
        self.policy = policy or Argon2Policy()
        self._hasher = PasswordHasher(
            time_cost=self.policy.time_cost,
            memory_cost=self.policy.memory_cost,
            parallelism=self.policy.parallelism,
            hash_len=self.policy.hash_length,
            salt_len=self.policy.salt_length,
        )

    def _with_pepper(self, password: str) -> str:
        if self.policy.pepper:
            return password + self.policy.pepper
        return password

    def hash(self, password: str) -> str:
        if not password:
            raise HashingError("Password cannot be empty")
        return self._hasher.hash(self._with_pepper(password))

    def verify(self, stored_hash: str | None, password: str | None) -> bool:
        if not stored_hash or not password:
            return False
        try:
            return self._hasher.verify(stored_hash, self._with_pepper(password))
        except VerifyMismatchError:
            return False
        except Exception as e:
            raise VerificationError(f"Argon2 verification failed: {e}") from e
