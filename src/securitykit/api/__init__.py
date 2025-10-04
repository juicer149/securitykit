"""
securitykit.api
================
Public API surface (lazy). Symbols are resolved on demand.

This module exposes the stable, public interface of SecurityKit while
deferring imports until a symbol is actually used — improving import
performance and avoiding unnecessary side effects.
"""

from __future__ import annotations
from typing import Any, Tuple
import importlib

from securitykit.hashing.registry import load_all as _load_all

__all__ = [
    # Hashing façade and factory
    "Algorithm",
    "HashingFactory",

    # Algorithm registry
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",

    # Policy registry
    "register_policy",
    "list_policies",
    "get_policy_class",

    # Policy classes
    "Argon2Policy",
    "BcryptPolicy",

    # Password system
    "PasswordPolicy",
    "PasswordValidator",

    # High-level API
    "hash_password",
    "verify_password",
    "rehash_password",
]


# ------------------------------------------------------------------------------
# Module mapping: maps public names → (module path, attribute name)
# ------------------------------------------------------------------------------
_MAPPING: dict[str, Tuple[str, str]] = {
    # Hashing façade and factory
    "Algorithm": ("securitykit.hashing.algorithm", "Algorithm"),
    "HashingFactory": ("securitykit.hashing.factory", "HashingFactory"),

    # Algorithm registry
    "register_algorithm": ("securitykit.hashing.algorithm_registry", "register_algorithm"),
    "list_algorithms": ("securitykit.hashing.algorithm_registry", "list_algorithms"),
    "get_algorithm_class": ("securitykit.hashing.algorithm_registry", "get_algorithm_class"),

    # Policy registry
    "register_policy": ("securitykit.hashing.policy_registry", "register_policy"),
    "list_policies": ("securitykit.hashing.policy_registry", "list_policies"),
    "get_policy_class": ("securitykit.hashing.policy_registry", "get_policy_class"),

    # Policies
    "Argon2Policy": ("securitykit.hashing.policies.argon2", "Argon2Policy"),
    "BcryptPolicy": ("securitykit.hashing.policies.bcrypt", "BcryptPolicy"),

    # Password policy and validation
    "PasswordPolicy": ("securitykit.password.policy", "PasswordPolicy"),
    "PasswordValidator": ("securitykit.password.validator", "PasswordValidator"),

    # High-level API functions
    "hash_password": ("securitykit.api.password_security", "hash_password"),
    "verify_password": ("securitykit.api.password_security", "verify_password"),
    "rehash_password": ("securitykit.api.password_security", "rehash_password"),
}


# ------------------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------------------
_cache: dict[str, Any] = {}  # Cache resolved symbols to avoid re-imports


def _import_attr(module_path: str, attr_name: str) -> Any:
    """Dynamically import a module and retrieve an attribute from it."""
    mod = importlib.import_module(module_path)
    return getattr(mod, attr_name)


# ------------------------------------------------------------------------------
# Dynamic attribute resolution
# ------------------------------------------------------------------------------
def __getattr__(name: str) -> Any:
    """Lazily resolve public attributes when accessed."""
    if name in _cache:
        return _cache[name]

    if name not in __all__:
        raise AttributeError(f"securitykit.api has no attribute '{name}'")

    # Ensure algorithm/policy registries are loaded before listing or lookups
    if name in ("list_algorithms", "list_policies", "get_algorithm_class", "get_policy_class"):
        _load_all()

    module_path, attr_name = _MAPPING[name]
    value = _import_attr(module_path, attr_name)
    _cache[name] = value
    return value


def __dir__() -> list[str]:
    """Ensure clean autocompletion in REPL / IDEs."""
    return sorted(__all__)
