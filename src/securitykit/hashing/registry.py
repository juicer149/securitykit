import importlib
import pkgutil
from typing import Callable, TypeVar, Generic

from securitykit.logging_config import logger

T = TypeVar("T")


class Registry(Generic[T]):
    def __init__(self, name: str, validator: Callable[[type], None] | None = None):
        self._name = name
        self._registry: dict[str, type[T]] = {}
        self._validator = validator

    def register(self, key: str) -> Callable[[type[T]], type[T]]:
        def decorator(cls: type[T]) -> type[T]:
            k = key.lower()
            if k in self._registry:
                logger.debug("%s '%s' already registered, skipping", self._name, k)
                return cls
            if self._validator:
                self._validator(cls)
            self._registry[k] = cls
            logger.debug("Registered %s: %s -> %s", self._name, k, cls.__name__)
            return cls
        return decorator

    def get(self, key: str) -> type[T]:
        try:
            return self._registry[key.lower()]
        except KeyError:
            raise KeyError(f"Unknown {self._name}: {key}")

    def list(self) -> list[str]:
        return list(self._registry.keys())

    def items(self) -> dict[str, type[T]]:
        return dict(self._registry)


_loaded = False
_snapshots_taken = False  # Have we performed initial module discovery?


def _autoload_package(package):
    """
    Imports all direct submodules of a package once (for decorator side-effects).
    """
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        full = f"{package.__name__}.{module_name}"
        importlib.import_module(full)


def load_all(force: bool = False) -> None:
    """
    Discover and register all policies & algorithms.

    First ever call:
        - imports submodules (decorators run, registry populated)
        - snapshots captured by registries' decorator logic
    Subsequent calls with force=False:
        - no-op
    Calls with force=True after snapshots:
        - clears registries
        - restores from snapshots (NO new class objects created)
    """
    global _loaded, _snapshots_taken
    if _loaded and not force:
        return

    from securitykit.hashing import algorithm_registry, policy_registry

    if not _snapshots_taken:
        import securitykit.hashing.policies as policies_pkg
        import securitykit.hashing.algorithms as algorithms_pkg
        _autoload_package(policies_pkg)
        _autoload_package(algorithms_pkg)
        _snapshots_taken = True
        logger.debug("Initial discovery done; snapshots captured.")
    elif force:
        algorithm_registry.restore_from_snapshots()
        policy_registry.restore_from_snapshots()
        logger.debug("Registries restored from snapshots (force=True).")

    _loaded = True
