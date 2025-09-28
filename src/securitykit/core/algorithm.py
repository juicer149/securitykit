# securitykit/core/algorithm.py
from typing import Any

from securitykit.core.algorithm_registry import get_algorithm_class
from securitykit.core.interfaces import AlgorithmProtocol
from securitykit.exceptions import HashingError, VerificationError
from securitykit.logging_config import logger


class Algorithm:
    """
    Abstraction over password hashing algorithms.
    Dynamically selects implementation from registry.
    Optionally injects a global pepper to all algorithms.
    """

    def __init__(self, variant: str, policy: Any = None, **kwargs: Any):
        algo_cls = get_algorithm_class(variant)
        self.impl: AlgorithmProtocol = algo_cls(policy, **kwargs)
        self.variant = variant.lower()
        logger.debug("Algorithm initialized with variant=%s, extra_args=%s", self.variant, kwargs)

    def hash(self, password: str) -> str:
        try:
            return self.impl.hash(password)
        except Exception as e:
            raise HashingError(f"Failed to hash password with {self.variant}: {e}") from e

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            return self.impl.verify(stored_hash, password)
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

    def __call__(self, password: str) -> str:
        return self.hash(password)

