from __future__ import annotations

import os
from typing import Any, Mapping

from securitykit.hashing.factory import HashingFactory
from securitykit.hashing.algorithm import Algorithm

# Optional public exports
__all__ = [
    "hash_password",
    "verify_password",
    "rehash_password",
    "Algorithm",
    "HashingFactory",
]

def _get_algo(config: Mapping[str, Any] | None = None) -> Algorithm:
    cfg = config or os.environ
    return HashingFactory(cfg).get_algorithm()

def hash_password(password: str, config: Mapping[str, Any] | None = None) -> str:
    return _get_algo(config).hash(password)

def verify_password(password: str, stored_hash: str, config: Mapping[str, Any] | None = None) -> bool:
    return _get_algo(config).verify(stored_hash, password)

def rehash_password(password: str, stored_hash: str, config: Mapping[str, Any] | None = None) -> str:
    """
    Verify then conditionally rehash using the CURRENT policy from config/env.
    Returns either the original hash (no rehash needed) or a new upgraded hash.
    """
    algo = _get_algo(config)
    if not algo.verify(stored_hash, password):
        return stored_hash
    if algo.needs_rehash(stored_hash):
        return algo.hash(password)
    return stored_hash
