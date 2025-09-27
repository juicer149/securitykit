# securitykit/core/algorithm_registry.py
import logging
from typing import Type, Callable

from securitykit.core.interfaces import AlgorithmProtocol
from securitykit.exceptions import UnknownAlgorithmError, RegistryConflictError

logger = logging.getLogger(__name__)

# Typalias
AlgorithmClass = Type[AlgorithmProtocol]

# Global registry over algoritmhs
_ALGORITHM_REGISTRY: dict[str, AlgorithmClass] = {}


def register_algorithm(name: str) -> Callable[[AlgorithmClass], AlgorithmClass]:
    """
    Class decorator to register an algorithm implementation in the global registry.
    """
    def decorator(cls: AlgorithmClass) -> AlgorithmClass:
        key = name.lower()
        if key in _ALGORITHM_REGISTRY:
            raise RegistryConflictError(f"Algorithm '{key}' is already registered.")
        _ALGORITHM_REGISTRY[key] = cls
        logger.debug("Registered algorithm: %s -> %s", key, cls.__name__)
        return cls
    return decorator


def get_algorithm_class(name: str) -> AlgorithmClass:
    key = name.lower()
    if key not in _ALGORITHM_REGISTRY:
        raise UnknownAlgorithmError(f"Unsupported algorithm variant: {name}")
    return _ALGORITHM_REGISTRY[key]


def list_algorithms() -> list[str]:
    return list(_ALGORITHM_REGISTRY.keys())
