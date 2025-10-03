"""
Custom exception hierarchy for SecurityKit.

Each logical subsystem gets a concise, purpose‑specific set of exception
types. Call sites should raise the narrowest meaningful subclass to
allow selective handling (e.g. fallback, logging, metrics).
"""

# --- Base ------------------------------------------------------------------


class SecurityKitError(Exception):
    """Base class for all SecurityKit exceptions."""


# --- Configuration / Policies ----------------------------------------------


class ConfigValidationError(SecurityKitError):
    """General configuration validation failure."""


class InvalidPolicyError(ConfigValidationError):
    """A policy class is incorrectly implemented or registered."""


class InvalidPolicyConfig(ConfigValidationError):
    """A policy instance has invalid or unsafe values."""


class UnknownPolicyError(SecurityKitError):
    """Tried to use a policy not present in registry."""


# --- Algorithms -------------------------------------------------------------


class AlgorithmError(SecurityKitError):
    """General error in an algorithm implementation."""


class InvalidAlgorithmError(AlgorithmError):
    """An algorithm class is incorrectly implemented or registered."""


class UnknownAlgorithmError(AlgorithmError):
    """Tried to use an algorithm not present in registry."""


class HashingError(AlgorithmError):
    """Hashing operation failed (invalid input, underlying lib error, etc.)."""


class VerificationError(AlgorithmError):
    """Verification operation failed (unexpected internal error)."""


# --- Pepper (input transformation / augmentation) --------------------------


class PepperError(SecurityKitError):
    """
    Base class for all pepper related errors.

    Pepper failures are *not* algorithm failures; callers may decide to
    fall back to a no‑op strategy while still hashing the password.
    """


class PepperStrategyRegistrationError(PepperError):
    """A pepper strategy attempted to register a duplicate or invalid name."""


class UnknownPepperStrategyError(PepperError):
    """Requested an unknown pepper strategy/mode."""


class PepperConfigError(PepperError, ConfigValidationError):
    """
    Invalid pepper configuration (missing required keys, bad HMAC key, etc.).
    """


class PepperStrategyConstructionError(PepperError):
    """Failed to construct a pepper strategy (bad parameters or runtime failure)."""


# --- Registry ---------------------------------------------------------------


class RegistryConflictError(SecurityKitError):
    """Tried to register a duplicate algorithm or policy."""


# --- Rehashing --------------------------------------------------------------


class RehashDecisionError(SecurityKitError):
    """Failed to decide if rehashing is required."""
