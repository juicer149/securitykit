from __future__ import annotations

from typing import ClassVar

try:
    from argon2 import PasswordHasher, exceptions as a2_exc  # type: ignore[reportMissingImports]
    _A2_AVAILABLE = True
except Exception:
    PasswordHasher = None  # type: ignore[assignment]
    a2_exc = None  # type: ignore[assignment]
    _A2_AVAILABLE = False

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.exceptions import HashingError


if _A2_AVAILABLE:

    @register_algorithm("argon2")
    class Argon2:
        """
        Argon2 implementation via argon2-cffi PasswordHasher.
        - hash_raw: raises HashingError on unexpected failures.
        - verify_raw: returns False only for VerifyMismatchError; lets other errors bubble.
        - needs_rehash: uses PasswordHasher.check_needs_rehash.
        """
        DEFAULT_POLICY_CLS: ClassVar[type[Argon2Policy]] = Argon2Policy

        def __init__(self, policy: Argon2Policy | None = None):
            policy = policy or Argon2Policy()
            if not isinstance(policy, Argon2Policy):
                raise TypeError("policy must be Argon2Policy")
            self.policy = policy
            self._ph = PasswordHasher(
                time_cost=policy.time_cost,
                memory_cost=policy.memory_cost,
                parallelism=policy.parallelism,
                hash_len=policy.hash_length,
            )

        def hash_raw(self, peppered_password: str) -> str:
            if not peppered_password:
                raise HashingError("Password cannot be empty")
            try:
                return self._ph.hash(peppered_password)
            except Exception as e:
                raise HashingError(f"Argon2 hash failed: {e}") from e

        def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
            # False for password mismatch; other exceptions bubble to Algorithm (central handling).
            if not stored_hash or not peppered_password:
                return False
            try:
                return self._ph.verify(stored_hash, peppered_password)
            except Exception as e:
                if a2_exc is not None and isinstance(e, getattr(a2_exc, "VerifyMismatchError", Exception)):
                    return False
                raise

        def needs_rehash(self, stored_hash: str) -> bool:
            try:
                return self._ph.check_needs_rehash(stored_hash)
            except Exception:
                return False
