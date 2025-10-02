from securitykit.hashing.registry import Registry
from securitykit.hashing.interfaces import AlgorithmProtocol
from securitykit.exceptions import UnknownAlgorithmError

# Underliggande registry
_algorithm_registry = Registry[AlgorithmProtocol]("algorithm")

# Snapshot-lista (key, klassobjekt). Behåller originalklassernas identitet.
_registered_algorithm_snapshots: list[tuple[str, type[AlgorithmProtocol]]] = []


def register_algorithm(name: str):
    """
    Decorator to register an algorithm under a given name.
    Also stores a snapshot (only once) so registry can be restored after a clear().
    """
    def decorator(cls: type[AlgorithmProtocol]) -> type[AlgorithmProtocol]:
        cls2 = _algorithm_registry.register(name)(cls)
        lowered = name.lower()
        if not any(k == lowered and c is cls2 for k, c in _registered_algorithm_snapshots):
            _registered_algorithm_snapshots.append((lowered, cls2))
        return cls2
    return decorator


def restore_from_snapshots() -> None:
    """
    Restore registry content from previously captured snapshots.
    Does NOT recreate classes, so isinstance remains stable.
    """
    _algorithm_registry._registry.clear()
    for key, cls in _registered_algorithm_snapshots:
        _algorithm_registry._registry[key] = cls


def get_algorithm_class(name: str) -> type[AlgorithmProtocol]:
    try:
        return _algorithm_registry.get(name)
    except KeyError as e:
        raise UnknownAlgorithmError(str(e)) from e


def list_algorithms() -> list[str]:
    return _algorithm_registry.list()
