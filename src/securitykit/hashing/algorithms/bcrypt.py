from __future__ import annotations
from typing import ClassVar

try:
    import bcrypt  # type: ignore[import-not-found]
except Exception as e:  # pragma: no cover
    raise RuntimeError("bcrypt library is required for Bcrypt algorithm") from e

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.bcrypt import BcryptPolicy
from securitykit.exceptions import HashingError, VerificationError


@register_algorithm("bcrypt")
class Bcrypt:
    """
    Bcrypt implementation expecting already peppered password input in hash_raw/verify_raw.
    """
    DEFAULT_POLICY_CLS: ClassVar[type[BcryptPolicy]] = BcryptPolicy

    def __init__(self, policy: BcryptPolicy | None = None):
        policy = policy or BcryptPolicy()
        if not isinstance(policy, BcryptPolicy):
            raise TypeError("policy must be BcryptPolicy")
        self.policy = policy

    def hash_raw(self, peppered_password: str) -> str:
        if not peppered_password:
            raise HashingError("Password cannot be empty")
        return bcrypt.hashpw(
            peppered_password.encode("utf-8"),
            bcrypt.gensalt(rounds=self.policy.rounds),
        ).decode("utf-8")

    def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
        if not stored_hash or not peppered_password:
            return False
        try:
            return bcrypt.checkpw(
                peppered_password.encode("utf-8"), stored_hash.encode("utf-8")
            )
        except Exception as e:
            raise VerificationError(f"Bcrypt verify failed: {e}") from e

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            parts = stored_hash.split("$")
            cost = int(parts[2])
            return cost < self.policy.rounds
        except Exception:
            return False
