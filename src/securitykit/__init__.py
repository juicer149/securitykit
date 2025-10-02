"""
SecurityKit – modular password hashing and policy enforcement.

Top-level namespace kept intentionally minimal to avoid heavy side effects on import.
Explicit loading of hashing algorithms/policies is done via:
    from securitykit.hashing.registry import load_all
or indirectly (lazy) through HashingFactory / Algorithm usage.
"""
from .version import __version__
from securitykit.logging_config import logger
from securitykit.exceptions import (
    SecurityKitError,
    ConfigValidationError,
    InvalidPolicyConfig,
    UnknownAlgorithmError,
    UnknownPolicyError,
)

__all__ = [
    "__version__",
    "logger",
    "SecurityKitError",
    "ConfigValidationError",
    "InvalidPolicyConfig",
    "UnknownAlgorithmError",
    "UnknownPolicyError",
]
