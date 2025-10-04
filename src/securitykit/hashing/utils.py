from __future__ import annotations

def detect_variant(stored_hash: str) -> str | None:
    """
    Best-effort detection of hashing algorithm variant from an encoded hash.

    Returns:
      - "argon2"           for $argon2... encodings (argon2-cffi)
      - "bcrypt"           for $2a$ / $2b$ / $2y$ encodings
      - "scrypt"           for $scrypt$ encodings (our custom format)
      - "werkzeug_pbkdf2"  for strings starting with "pbkdf2:"
      - None               if not recognized
    """
    if not stored_hash:
        return None
    s = stored_hash
    if s.startswith("$argon2"):
        return "argon2"
    if s.startswith("$2a$") or s.startswith("$2b$") or s.startswith("$2y$"):
        return "bcrypt"
    if s.startswith("$scrypt$"):
        return "scrypt"
    if s.startswith("pbkdf2:"):
        return "werkzeug_pbkdf2"
    return None


def is_foreign_variant(stored_hash: str, expected_variant: str) -> bool:
    """
    Return True if stored_hash appears to belong to another algorithm than expected_variant.
    """
    v = detect_variant(stored_hash)
    return v is not None and v != expected_variant
