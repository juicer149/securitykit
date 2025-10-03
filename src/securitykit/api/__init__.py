"""
securitykit.api
================
Public API surface (lazy). Symbols resolved on demand.
"""
from __future__ import annotations
from typing import Any
from securitykit.hashing.registry import load_all as _load_all

__all__ = [
    "Algorithm",
    "HashingFactory",
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",
    "register_policy",
    "list_policies",
    "get_policy_class",
    "Argon2Policy",
    "BcryptPolicy",
    "PasswordPolicy",
    "PasswordValidator",
    "hash_password",
    "verify_password",
    "rehash_password",
]

def _exports() -> dict[str, Any]:
    return {
        "Algorithm": lambda: __import__("securitykit.hashing.algorithm", fromlist=["Algorithm"]).hashing.algorithm.Algorithm,
        "HashingFactory": lambda: __import__("securitykit.hashing.factory", fromlist=["HashingFactory"]).hashing.factory.HashingFactory,
        "register_algorithm": lambda: __import__("securitykit.hashing.algorithm_registry", fromlist=["register_algorithm"]).hashing.algorithm_registry.register_algorithm,
        "list_algorithms": lambda: (_load_all() or __import__("securitykit.hashing.algorithm_registry", fromlist=["list_algorithms"]).hashing.algorithm_registry.list_algorithms()),
        "get_algorithm_class": lambda: __import__("securitykit.hashing.algorithm_registry", fromlist=["get_algorithm_class"]).hashing.algorithm_registry.get_algorithm_class,
        "register_policy": lambda: __import__("securitykit.hashing.policy_registry", fromlist=["register_policy"]).hashing.policy_registry.register_policy,
        "list_policies": lambda: (_load_all() or __import__("securitykit.hashing.policy_registry", fromlist=["list_policies"]).hashing.policy_registry.list_policies()),
        "get_policy_class": lambda: __import__("securitykit.hashing.policy_registry", fromlist=["get_policy_class"]).hashing.policy_registry.get_policy_class,
        "Argon2Policy": lambda: __import__("securitykit.hashing.policies.argon2", fromlist=["Argon2Policy"]).hashing.policies.argon2.Argon2Policy,
        "BcryptPolicy": lambda: __import__("securitykit.hashing.policies.bcrypt", fromlist=["BcryptPolicy"]).hashing.policies.bcrypt.BcryptPolicy,
        "PasswordPolicy": lambda: __import__("securitykit.password.policy", fromlist=["PasswordPolicy"]).password.policy.PasswordPolicy,
        "PasswordValidator": lambda: __import__("securitykit.password.validator", fromlist=["PasswordValidator"]).password.validator.PasswordValidator,
        "hash_password": lambda: __import__("securitykit.api.password_security", fromlist=["hash_password"]).api.password_security.hash_password,
        "verify_password": lambda: __import__("securitykit.api.password_security", fromlist=["verify_password"]).api.password_security.verify_password,
        "rehash_password": lambda: __import__("securitykit.api.password_security", fromlist=["rehash_password"]).api.password_security.rehash_password,
    }

def __getattr__(name: str) -> Any:
    if name not in __all__:
        raise AttributeError(f"securitykit.api has no attribute '{name}'")
    return _exports()[name]()
