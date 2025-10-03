from __future__ import annotations
from typing import Dict, Type

from securitykit.exceptions import RegistryConflictError, UnknownPolicyError

_POLICIES: Dict[str, Type] = {}
_SNAPSHOTS: Dict[str, Type] = {}


def register_policy(name: str):
    norm = name.lower()

    def decorator(cls: Type):
        existing = _POLICIES.get(norm)
        if existing is not None and existing is not cls:
            raise RegistryConflictError(
                f"Policy variant '{name}' already registered with {existing.__name__}"
            )
        _POLICIES[norm] = cls
        if norm not in _SNAPSHOTS:
            _SNAPSHOTS[norm] = cls
        return cls

    return decorator


def get_policy_class(name: str) -> Type:
    cls = _POLICIES.get(name.lower())
    if cls is None:
        raise UnknownPolicyError(f"Unknown policy variant '{name}'")
    return cls


def list_policies() -> list[str]:
    return sorted(_POLICIES.keys())


def list_policy_classes() -> dict[str, Type]:
    return dict(_POLICIES)


def restore_from_snapshots() -> None:
    _POLICIES.clear()
    _POLICIES.update(_SNAPSHOTS)


__all__ = [
    "register_policy",
    "get_policy_class",
    "list_policies",
    "list_policy_classes",
    "restore_from_snapshots",
]
