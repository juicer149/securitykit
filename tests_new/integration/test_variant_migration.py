import itertools
import os

import pytest

from securitykit.api.migration import authenticate_and_upgrade
from securitykit.hashing.factory import HashingFactory
from securitykit.hashing import algorithm_registry
from ..common.helpers import VALID_PASSWORD


def _build_cfg_for_variant(variant: str, strength: str) -> dict:
    """
    Return a mapping config for a given variant.
    strength: 'low' or 'high' (choose parameters to make 'high' strictly stronger).
    """
    if variant == "argon2":
        return {
            "HASH_VARIANT": "argon2",
            "ARGON2_TIME_COST": 2 if strength == "low" else 4,
            "ARGON2_MEMORY_COST": 65536 if strength == "low" else 131072,
            "ARGON2_PARALLELISM": 1 if strength == "low" else 2,
        }
    if variant == "bcrypt":
        return {
            "HASH_VARIANT": "bcrypt",
            "BCRYPT_ROUNDS": 10 if strength == "low" else 12,
        }
    if variant == "scrypt":
        return {
            "HASH_VARIANT": "scrypt",
            "SCRYPT_N": (2**13) if strength == "low" else (2**14),
            "SCRYPT_R": 8,
            "SCRYPT_P": 1,
            "SCRYPT_SALT_LENGTH": 16,
            "SCRYPT_HASH_LENGTH": 32,
        }
    if variant == "werkzeug_pbkdf2":
        try:
            import werkzeug  # noqa: F401
        except Exception:
            pytest.skip("Werkzeug not installed/registered")
        return {
            "HASH_VARIANT": "werkzeug_pbkdf2",
            "WERKZEUG_PBKDF2_METHOD": "pbkdf2:sha256",
            "WERKZEUG_PBKDF2_ITERATIONS": 150_000 if strength == "low" else 260_000,
            "WERKZEUG_PBKDF2_SALT_LENGTH": 16,
        }
    pytest.skip(f"Unknown/unsupported variant for migration test: {variant}")


def test_cross_variant_migration_all_pairs():
    """
    For every pair of registered algorithms (src != dst):
      - Create a hash with src (low strength).
      - Authenticate and upgrade to dst (high strength/current variant).
      - Assert the upgraded hash verifies under dst and differs from original.
    """
    algos = algorithm_registry.list_algorithms()
    pairs = [(s, d) for s, d in itertools.product(algos, algos) if s != d]
    if not pairs:
        pytest.skip("No algorithm pairs available for migration test.")

    for src, dst in pairs:
        src_cfg = _build_cfg_for_variant(src, "low")
        dst_cfg = _build_cfg_for_variant(dst, "high")

        # Produce a source hash with explicit source config
        algo_src = HashingFactory(src_cfg).get_algorithm()
        h_src = algo_src.hash(VALID_PASSWORD)
        assert algo_src.verify(h_src, VALID_PASSWORD) is True

        # Authenticate and upgrade using destination config
        ok, new_hash = authenticate_and_upgrade(VALID_PASSWORD, h_src, config=dst_cfg)
        assert ok is True
        assert new_hash is not None
        assert new_hash != h_src

        # Verify with destination algo
        algo_dst = HashingFactory(dst_cfg).get_algorithm()
        assert algo_dst.verify(new_hash, VALID_PASSWORD) is True

        # Sanity: old hash should not verify with destination algo
        assert algo_dst.verify(h_src, VALID_PASSWORD) is False

        # Wrong password must not migrate and must not verify
        ok2, new_hash2 = authenticate_and_upgrade("wrongpass", h_src, config=dst_cfg)
        assert ok2 is False
        assert new_hash2 is None
