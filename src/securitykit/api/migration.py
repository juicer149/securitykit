"""
Login-time authentication and automatic password hash upgrade/migration.

This module verifies a candidate password against its original hash variant
and, on success, upgrades or migrates it to the current configured algorithm/policy.
"""

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

    This function is typically called during login. It allows seamless migration
    of legacy hashes whenever policies or algorithms evolve.

    Behavior:
      • Detects the source variant from the encoded hash.
      • Verifies using the detected source algorithm.
      • If the destination variant matches and needs_rehash=True → rehashes.
      • If the destination variant differs → migrates automatically.
      • Returns (ok, new_hash):
          - ok: True if password matched; False otherwise
          - new_hash: new hash if rehashed/migrated, else None

    Parameters:
      password:
          The plaintext password provided by the user.
      stored_hash:
          The existing encoded hash string from storage.
      config:
          A mapping of configuration keys (e.g. os.environ or dict):
            - HASH_VARIANT
            - Variant-specific policy keys (e.g. ARGON2_*, SCRYPT_*, etc.)
            - Optional PEPPER_* keys (used by the pepper subsystem)

    Notes:
      - This function does NOT perform password policy gating or strength checks.
        Those belong at registration/change time — not during login.
      - Pepper configuration is reused automatically for both source and
        destination algorithms (ensuring legacy compatibility).

    Example:
      dest_cfg = {
          "HASH_VARIANT": "argon2",
          "ARGON2_TIME_COST": 3,
          "ARGON2_MEMORY_COST": 131072,
          "ARGON2_PARALLELISM": 2,
      }

      ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
      if ok and new_hash is not None:
          persist(new_hash)
    """
    cfg = config or os.environ

    # --- Destination algorithm and variant ---
    dest_algo = HashingFactory(cfg).get_algorithm()
    dst_variant = dest_algo.variant

    # --- Detect source variant from encoded hash ---
    src_variant = detect_variant(stored_hash)
    if not src_variant:
        return False, None

    # --- Build source algorithm using the same config but forced variant ---
    src_cfg = dict(cfg)
    src_cfg["HASH_VARIANT"] = src_variant

    try:
        src_algo = HashingFactory(src_cfg).get_algorithm()
    except UnknownAlgorithmError:
        # Source variant not installed or recognized in this environment
        return False, None

    # --- Verify against detected source algorithm ---
    if not src_algo.verify(stored_hash, password):
        return False, None

    # --- Same-variant path: upgrade only if parameters changed ---
    if src_variant == dst_variant:
        if dest_algo.needs_rehash(stored_hash):
            return True, dest_algo.hash(password)
        return True, None

    # --- Cross-variant migration path ---
    return True, dest_algo.hash(password)
