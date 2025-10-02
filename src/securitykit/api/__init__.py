"""
securitykit.api
================
Public API for end users. Import everything you need from here.
"""

# Hashing
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.algorithm_registry import (
    register_algorithm,
    list_algorithms,
    get_algorithm_class,
)
from securitykit.hashing.policy_registry import (
    register_policy,
    list_policies,
    get_policy_class,
)

# Policies
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.password.policy import PasswordPolicy

# Password utilities
from securitykit.password.validator import PasswordValidator

# High-level API
from securitykit.api.password_security import (
    hash_password,
    verify_password,
    rehash_password,
)

__all__ = [
    # Hashing
    "Algorithm",
    "HashingFactory",
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",
    "register_policy",
    "list_policies",
    "get_policy_class",

    # Policies
    "Argon2Policy",
    "PasswordPolicy",

    # Password
    "PasswordValidator",

    # High-level API
    "hash_password",
    "verify_password",
    "rehash_password",
]
