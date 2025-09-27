# securitykit/core/policy_registry.py
import logging

from securitykit.exceptions import UnknownPolicyError, RegistryConflictError

logger = logging.getLogger(__name__)

_POLICY_REGISTRY: dict[str, type] = {}


def register_policy(name: str):
    """Decorator to register a policy class in the global registry."""
    def decorator(cls: type) -> type:
        key = name.lower()
        if key in _POLICY_REGISTRY:
            raise RegistryConflictError(f"Policy '{key}' is already registered.")
        _POLICY_REGISTRY[key] = cls
        logger.debug("Registered policy: %s -> %s", key, cls.__name__)
        return cls
    return decorator


def get_policy_class(name: str) -> type:
    key = name.lower()
    if key not in _POLICY_REGISTRY:
        raise UnknownPolicyError(f"Unsupported policy: {name}")
    return _POLICY_REGISTRY[key]


def list_policies() -> list[str]:
    return list(_POLICY_REGISTRY.keys())
