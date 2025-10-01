"""
SecurityKit – A modular security toolkit for password hashing and policy enforcement.
"""
from securitykit.logging_config import logger
from securitykit.core.algorithm import Algorithm
from securitykit.core.factory import SecurityFactory
from securitykit.core.registry import load_all
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
from securitykit.policies.password import PasswordPolicy
from securitykit.policies.argon2 import Argon2Policy
from securitykit.exceptions import (
    SecurityKitError,
    ConfigValidationError,
    InvalidPolicyConfig,
)
from .version import __version__

# Load all policies and algorithms at import
load_all()

__all__ = [
    "logger",
    "SecurityFactory",
    "Algorithm",
    "register_algorithm",
    "list_algorithms",
    "get_algorithm_class",
    "register_policy",
    "list_policies",
    "get_policy_class",
    "PasswordPolicy",
    "Argon2Policy",
    "SecurityKitError",
    "ConfigValidationError",
    "InvalidPolicyConfig",
    "load_all",
    "__version__",
]
