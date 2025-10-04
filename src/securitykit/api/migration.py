from __future__ import annotations

import os
from typing import Any, Mapping, Optional, Tuple

from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.utils import detect_variant
from securitykit.exceptions import UnknownAlgorithmError


def authenticate_and_upgrade(
    password: str,
    stored_hash: str,
    *,
    config: Mapping[str, Any] | None = None,
) -> Tuple[bool, Optional[str]]:
    """
    Authenticate a password against its original hash algorithm and, if valid,
    optionally upgrade or migrate the hash to the current algorithm/policy.

    Intended usage: call this during login to seamlessly migrate legacy hashes
    whenever you tighten policy parameters or switch HASH_VARIANT (e.g., from
    bcrypt/werkzeug to argon2). If the password is correct, this function will
    either:
      - Re-hash with the same algorithm if needs_rehash returns True (policy upgrade), or
      - Re-hash with the current/destination algorithm if the variant changed (migration).

    Parameters:
      password:
        The clear-text password provided by the user during authentication.
      stored_hash:
        The existing encoded hash stored for the user (may belong to any supported variant).
      config:
        A mapping that defines the "destination" algorithm and policy. Typical keys include:
          - HASH_VARIANT (e.g., "argon2", "bcrypt", "scrypt", "werkzeug_pbkdf2")
          - Variant-specific policy keys (e.g., ARGON2_*, BCRYPT_*, SCRYPT_*, WERKZEUG_PBKDF2_*)
          - Optional PEPPER_* keys used by the pepper pipeline.
        If omitted, os.environ is used.

    Returns:
      (ok, new_hash) where:
        - ok: True if the password matched under the detected source variant; otherwise False.
        - new_hash: A newly produced hash string if an upgrade/migration was performed, else None.

    Notes:
      - Source variant detection is best-effort via detect_variant() from the encoded hash format.
      - The function verifies with the detected source variant using the SAME config mapping,
        but forces HASH_VARIANT to the source value for verification.
      - Pepper: both verification and re-hash use the provided config mapping. If legacy hashes
        were created with different PEPPER_* settings, include transitional PEPPER_* values in
        `config` so verification succeeds before re-hashing with the new policy.

    Example:
      dest_cfg = {
          "HASH_VARIANT": "argon2",
          "ARGON2_TIME_COST": 3,
          "ARGON2_MEMORY_COST": 131072,
          "ARGON2_PARALLELISM": 2,
          # Optional transitional pepper if legacy hashes used pepper:
          # "PEPPER_MODE": "suffix",
          # "PEPPER_SUFFIX": "_LEGACY",
      }
      ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
      if ok and new_hash is not None:
          persist(new_hash)
    """
    cfg = config or os.environ

    # Destination algorithm (the "current" policy/variant).
    dest_algo = HashingFactory(cfg).get_algorithm()
    dst_variant = dest_algo.variant

    # Detect the source variant from the stored hash.
    src_variant = detect_variant(stored_hash)
    if not src_variant:
        return False, None

    # Build the source algorithm using the same config but force HASH_VARIANT to the detected source.
    src_cfg = dict(cfg)
    src_cfg["HASH_VARIANT"] = src_variant
    try:
        src_algo = HashingFactory(src_cfg).get_algorithm()
    except UnknownAlgorithmError:
        # Source variant not installed/registered in this environment; cannot verify.
        return False, None

    # Verify with the source algorithm.
    if not src_algo.verify(stored_hash, password):
        return False, None

    # Same-variant path: only re-hash if policy has been tightened (needs_rehash=True).
    if src_variant == dst_variant:
        if dest_algo.needs_rehash(stored_hash):
            return True, dest_algo.hash(password)
        return True, None

    # Cross-variant migration: always produce a new hash with the destination algorithm/policy.
    return True, dest_algo.hash(password)
