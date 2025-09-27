"""
Custom exception hierarchy for SecurityKit.
"""


class SecurityKitError(Exception):
    """Base class for all SecurityKit exceptions."""


# --- Config / Policies ---
class ConfigValidationError(SecurityKitError):
    """General configuration validation failure."""


class InvalidPolicyError(SecurityKitError):
    """A policy class is incorrectly implemented or registered."""


class InvalidPolicyConfig(ConfigValidationError):
    """A policy instance has invalid or unsafe values."""


class UnknownPolicyError(SecurityKitError):
    """Tried to use a policy not present in registry."""


# --- Algorithms ---
class UnknownAlgorithmError(SecurityKitError):
    """Tried to use an algorithm not present in registry."""


class AlgorithmError(SecurityKitError):
    """General error in an algorithm implementation."""


class HashingError(AlgorithmError):
    """Hashing operation failed."""


class VerificationError(AlgorithmError):
    """Verification operation failed."""


# --- Registry ---
class RegistryConflictError(SecurityKitError):
    """Tried to register a duplicate algorithm or policy."""


# --- Rehashing ---
class RehashDecisionError(SecurityKitError):
    """Failed to decide if rehashing is required."""
