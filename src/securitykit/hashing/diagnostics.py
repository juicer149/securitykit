"""
securitykit.hashing.diagnostics
-------------------------------

Centralized runtime diagnostics for all supported hashing algorithms.

• Collects CapabilityInfo from each algorithm module (if available)
• Provides a cached snapshot for registry and policy introspection
• Does NOT import algorithm internals (avoids circular dependencies)
"""

from __future__ import annotations
from functools import lru_cache
from securitykit.hashing.capabilities import CapabilityInfo

# Import diagnostic providers for each algorithm
# Each algorithm module should expose a get_<variant>_diagnostics() function
from securitykit.hashing.algorithms.bcrypt import get_bcrypt_diagnostics
from securitykit.hashing.algorithms.scrypt import get_scrypt_diagnostics
from securitykit.hashing.algorithms.wz_pbkdf2 import get_werkzeug_pbkdf2_diagnostics

# Argon2 diagnostics are now handled via the new CapabilityInfo snapshot,
# so we do not import from hashing.algorithms.argon2 directly anymore.
# Instead, we define a minimal compatibility shim here.
def get_argon2_diagnostics() -> CapabilityInfo:
    """
    Compatibility shim for Argon2 diagnostics.

    The real Argon2 diagnostic data is gathered dynamically
    in the registry via CapabilityInfo and passed to policies.
    """
    try:
        from argon2 import __version__ as a2_version
        from argon2 import PasswordHasher
        supports_secret = "secret" in PasswordHasher.__init__.__code__.co_varnames
        available = True
    except Exception:
        a2_version = "unknown"
        supports_secret = False
        available = False

    return CapabilityInfo(
        available=available,
        version=a2_version,
        extra={"supports_secret": supports_secret},
    )


@lru_cache(maxsize=1)
def collect_all_diagnostics() -> dict[str, CapabilityInfo]:
    """
    Collect and cache all hashing algorithm diagnostics.

    Returns:
        dict[str, CapabilityInfo] keyed by variant name.
    """
    return {
        "argon2": get_argon2_diagnostics(),
        "bcrypt": get_bcrypt_diagnostics(),
        "scrypt": get_scrypt_diagnostics(),
        "werkzeug_pbkdf2": get_werkzeug_pbkdf2_diagnostics(),
    }
