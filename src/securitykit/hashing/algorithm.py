# securitykit/hashing/algorithm.py
from typing import Any

from securitykit.hashing.algorithm_registry import get_algorithm_class
from securitykit.hashing.interfaces import AlgorithmProtocol, PolicyProtocol
from securitykit.exceptions import HashingError, VerificationError
from securitykit.logging_config import logger


class Algorithm:
    """
    Abstraction over password hashing algorithms.
    Dynamically selects implementation from registry.
    Applies a global pepper orthogonally to all algorithms.
    """

    def __init__(self, variant: str, policy: Any = None, pepper: str | None = None, **kwargs: Any):
        algo_cls = get_algorithm_class(variant)
        self.impl: AlgorithmProtocol = algo_cls(policy, **kwargs)
        self.variant = variant.lower()
        self.policy: PolicyProtocol | None = policy
        self.pepper = pepper  # orthogonal, applies to any algorithm if set
        logger.debug("Algorithm initialized with variant=%s, pepper=%s", self.variant, bool(pepper))

    def _with_pepper(self, password: str) -> str:
        if self.pepper:
            return password + self.pepper
        return password

    def hash(self, password: str) -> str:
        try:
            return self.impl.hash(self._with_pepper(password))
        except Exception as e:
            raise HashingError(f"Failed to hash password with {self.variant}: {e}") from e

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self.impl.verify(stored_hash, self._with_pepper(password))
        except Exception as e:
            raise VerificationError(f"Failed to verify password with {self.variant}: {e}") from e

    def needs_rehash(self, stored_hash: str) -> bool:
        """Return True if the stored hash should be rehashed (e.g. params changed)."""
        if not hasattr(self.impl, "needs_rehash"):
            return False
        try:
            return self.impl.needs_rehash(stored_hash)
        except Exception as e:
            logger.error("Needs_rehash failed for %s: %s", self.variant, e)
            return False

    def get_policy_dict(self) -> dict[str, Any]:
        """
        Return the current policy as a dict, if available.
        """
        if self.policy and hasattr(self.policy, "to_dict"):
            return self.policy.to_dict()
        return {}

    def __call__(self, password: str) -> str:
        return self.hash(password)
