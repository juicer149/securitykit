# securitykit/core/algorithm_registry.py
from securitykit import logger
from securitykit.core.registry import Registry
from securitykit.exceptions import UnknownAlgorithmError
from securitykit.core.interfaces import AlgorithmProtocol


def _validate_algorithm(cls: type) -> None:
    """
    Extra krav för algoritmer:
    - Måste implementera AlgorithmProtocol (duck typing räcker).
    """
    # samma fråga här som i policy_registry.py, ska jag ah en egen exception för detta?
    for method in ("hash", "verify", "needs_rehash"):
        if not hasattr(cls, method):
            raise TypeError(f"Algorithm {cls.__name__} missing required method: {method}")


# Create registry for algorithms
_algorithm_registry = Registry("algorithm", validator=_validate_algorithm)


def register_algorithm(name: str):
    return _algorithm_registry.register(name)


def get_algorithm_class(name: str) -> type[AlgorithmProtocol]:
    try:
        return _algorithm_registry.get(name)
    except KeyError as e:
        raise UnknownAlgorithmError(str(e))


def list_algorithms() -> list[str]:
    return _algorithm_registry.list()
