"""
SecurityKit – A modular security toolkit for password hashing and policy enforcement.

This package provides:
- Public API for algorithms and policies
- Global registries for algorithms and policies
- Pre-registered defaults (PasswordPolicy, Argon2Policy, Argon2/Password algorithms)
"""

from securitykit.core.algorithm import Algorithm
from securitykit.core.factory import SecurityFactory
from securitykit.exceptions import (
    SecurityKitError,
    ConfigValidationError,
    InvalidPolicyConfig,
)
from securitykit.core.algorithm_registry import (
    register_algorithm,
    list_algorithms,
    get_algorithm_class,
)
from securitykit.core.policy_registry import (
    register_policy,
    list_policies,
    get_policy_class,
)
from securitykit.policies.password import PasswordPolicy  # auto-registered via decorator
from securitykit.policies.argon2 import Argon2Policy      # auto-registered via decorator

# Import algorithms so they self-register in the registry
from securitykit.algorithms import argon2, password  # noqa: F401


__all__ = [
    # Factories
    "SecurityFactory",
    # Algorithm API
    "Algorithm",
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",
    # Policy API
    "register_policy",
    "list_policies",
    "get_policy_class",
    # Common policies
    "PasswordPolicy",
    "Argon2Policy",
    # Exceptions
    "SecurityKitError",
    "ConfigValidationError",
    "InvalidPolicyConfig",
]
