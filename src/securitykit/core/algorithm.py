# securitykit/core/algorithm.py
import logging
from typing import Any

from securitykit.core.algorithm_registry import get_algorithm_class
from securitykit.core.interfaces import AlgorithmProtocol
from securitykit.exceptions import HashingError, VerificationError

logger = logging.getLogger(__name__)


class Algorithm:
    """
    Abstraction over password hashing algorithms.
    Dynamically selects implementation from registry.
    """

    def __init__(self, variant: str, policy: Any = None):
        algo_cls = get_algorithm_class(variant)
        self.impl: AlgorithmProtocol = algo_cls(policy)
        self.variant = variant.lower()
        logger.debug("Algorithm initialized with variant=%s", self.variant)

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

    def __call__(self, password: str) -> str:
        return self.hash(password)
