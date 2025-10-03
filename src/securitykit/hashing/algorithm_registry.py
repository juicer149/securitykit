from __future__ import annotations
from typing import Dict, Type

from securitykit.exceptions import RegistryConflictError, UnknownAlgorithmError

_ALGORITHMS: Dict[str, Type] = {}
_SNAPSHOTS: Dict[str, Type] = {}


def register_algorithm(name: str):
    """
    Register an algorithm class under a variant (case-insensitive).
    Safe to call multiple times with the *same* class; raises on different class.
    """
    norm = name.lower()

    def decorator(cls: Type):
        existing = _ALGORITHMS.get(norm)
        if existing is not None and existing is not cls:
            raise RegistryConflictError(
                f"Algorithm variant '{name}' already registered with {existing.__name__}"
            )
        _ALGORITHMS[norm] = cls
        if norm not in _SNAPSHOTS:
            _SNAPSHOTS[norm] = cls
        return cls

    return decorator


def get_algorithm_class(name: str) -> Type:
    cls = _ALGORITHMS.get(name.lower())
    if cls is None:
        raise UnknownAlgorithmError(f"Unknown algorithm variant '{name}'")
    return cls


def list_algorithms() -> list[str]:
    return sorted(_ALGORITHMS.keys())


def list_algorithm_classes() -> dict[str, Type]:
    return dict(_ALGORITHMS)


def restore_from_snapshots() -> None:
    _ALGORITHMS.clear()
    _ALGORITHMS.update(_SNAPSHOTS)


__all__ = [
    "register_algorithm",
    "get_algorithm_class",
    "list_algorithms",
    "list_algorithm_classes",
    "restore_from_snapshots",
]
