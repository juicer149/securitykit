from securitykit.hashing.registry import Registry
from securitykit.hashing.interfaces import PolicyProtocol
from securitykit.exceptions import UnknownPolicyError  # Om denna finns, annars skapa/justera.

_policy_registry = Registry[PolicyProtocol]("policy")
_registered_policy_snapshots: list[tuple[str, type[PolicyProtocol]]] = []


def register_policy(name: str):
    """
    Decorator to register a policy under a given name.
    Also records a snapshot of the class for later restoration.
    """
    def decorator(cls: type[PolicyProtocol]) -> type[PolicyProtocol]:
        cls2 = _policy_registry.register(name)(cls)
        lowered = name.lower()
        if not any(k == lowered and c is cls2 for k, c in _registered_policy_snapshots):
            _registered_policy_snapshots.append((lowered, cls2))
        return cls2
    return decorator


def restore_from_snapshots() -> None:
    _policy_registry._registry.clear()
    for key, cls in _registered_policy_snapshots:
        _policy_registry._registry[key] = cls


def get_policy_class(name: str) -> type[PolicyProtocol]:
    try:
        return _policy_registry.get(name)
    except KeyError as e:
        raise UnknownPolicyError(str(e)) from e


def list_policies() -> list[str]:
    return _policy_registry.list()
