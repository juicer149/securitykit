"""
securitykit.hashing.utils
-------------------------

Utility helpers for SecurityKit hashing subsystem.

Includes:
    • detect_variant(): Detect algorithm from hash prefix.
    • is_foreign_variant(): Compare hash to expected variant.
"""

from __future__ import annotations
from typing import Optional


# ---------------------------------------------------------------------------
# Variant detection utilities
# ---------------------------------------------------------------------------

def detect_variant(stored_hash: str) -> Optional[str]:
    """
    Best-effort detection of hashing algorithm variant from an encoded hash.

    Returns:
      - "argon2"           for $argon2... encodings (argon2-cffi)
      - "bcrypt"           for $2a$ / $2b$ / $2y$ encodings
      - "scrypt"           for $scrypt$ encodings (SecurityKit custom)
      - "werkzeug_pbkdf2"  for strings starting with "pbkdf2:"
      - None               if not recognized
    """
    if not stored_hash:
        return None
    s = stored_hash
    if s.startswith("$argon2"):
        return "argon2"
    if s.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt"
    if s.startswith("$scrypt$"):
        return "scrypt"
    if s.startswith("pbkdf2:"):
        return "werkzeug_pbkdf2"
    return None


def is_foreign_variant(stored_hash: str, expected_variant: str) -> bool:
    """
    Return True if stored_hash appears to belong to another algorithm
    than the expected variant.
    """
    v = detect_variant(stored_hash)
    return v is not None and v != expected_variant
