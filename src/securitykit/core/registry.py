# securitykit/core/registry.py
"""
Generic registry utility for SecurityKit.
Supports autoloading of all algorithms and policies.
"""

import importlib
import pkgutil
from typing import Callable, TypeVar, Generic

from securitykit.exceptions import RegistryConflictError
from securitykit.logging_config import logger

T = TypeVar("T")  # Generic type for registered classes


class Registry(Generic[T]):
    def __init__(self, name: str, validator: Callable[[type], None] | None = None):
        self._name = name
        self._registry: dict[str, type[T]] = {}
        self._validator = validator

    def register(self, key: str) -> Callable[[type[T]], type[T]]:
        """
        Decorator to register a class in the registry.
        Example:
            @my_registry.register("argon2")
            class Argon2Policy: ...
        """
        def decorator(cls: type[T]) -> type[T]:
            k = key.lower()
            if k in self._registry:
                raise RegistryConflictError(f"{self._name} '{k}' already registered.")

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


# -------------------
# Autoload mechanism
# -------------------
def _autoload_package(package):
    """Dynamically import all submodules in a package to trigger decorators."""
    for _, module_name, _ in pkgutil.iter_modules(package.__path__):
        importlib.import_module(f"{package.__name__}.{module_name}")


def load_all() -> None:
    """
    Ensure all algorithms and policies are loaded into their registries.
    """
    import securitykit.policies
    import securitykit.algorithms

    _autoload_package(securitykit.policies)
    _autoload_package(securitykit.algorithms)
    logger.debug("Autoloaded all policies and algorithms")
