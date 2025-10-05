"""
securitykit.hashing.algorithm
-----------------------------

Unified hashing façade that is variant-agnostic and pepper-aware.

Responsibilities:
  • Resolve algorithm implementation dynamically via registry
  • Integrate PepperFactory for deterministic pepper handling
  • Remain agnostic to variant-specific quirks (Argon2, bcrypt, etc.)
  • Provide a unified interface for hashing, verifying, and rehashing

This version relies on:
  - Cached diagnostics from `hashing.registry`
  - Argon2Policy for version and internal pepper support
  - PepperFactory for prehash or secret-based pepper integration
"""

from __future__ import annotations
from typing import Any, Mapping
import os

from securitykit.hashing.algorithm_registry import get_algorithm_class
from securitykit.exceptions import (
    HashingError,
    VerificationError,
    UnknownAlgorithmError,
)
from securitykit.logging_config import logger
from securitykit.hashing.utils import is_foreign_variant

# Pepper integration
from securitykit.transform.pepper.factory import PepperFactory, PepperApplication


class Algorithm:
    """
    High-level façade over a concrete hashing algorithm implementation.

    Responsibilities:
      - Resolve the variant class dynamically via registry.
      - Obtain a PepperApplication via PepperFactory:
          • prehash_pipeline(password)      → transform before hashing
          • algo_kwargs={"secret": ...}     → pass native secret (e.g., Argon2)
      - Provide a unified API: hash(), verify(), needs_rehash(), etc.
      - Surface consistent diagnostics and logging.
    """

    def __init__(
        self,
        variant: str,
        policy: Any = None,
        *,
        config: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ):
        self.variant = variant.lower()
        self.policy = policy
        self._config = config or os.environ

        # ---------------------------------------------------------------------
        # Resolve algorithm class
        # ---------------------------------------------------------------------
        try:
            algo_cls = get_algorithm_class(self.variant)
        except UnknownAlgorithmError as e:
            hints = {
                "argon2": "Install extra: pip install 'securitykit[alg_argon2]'",
                "bcrypt": "Install extra: pip install 'securitykit[alg_bcrypt]'",
                "werkzeug_pbkdf2": "Install extra: pip install 'securitykit[alg_werkzeug]'",
            }
            hint = hints.get(self.variant, "")
            msg = f"{e} {hint}".strip()
            raise UnknownAlgorithmError(msg) from e

        # ---------------------------------------------------------------------
        # Construct pepper application plan
        # ---------------------------------------------------------------------
        app: PepperApplication = PepperFactory.from_config(self.variant, self._config)
        self._prehash = app.prehash_pipeline
        self._algo_kwargs = app.algo_kwargs

        # ---------------------------------------------------------------------
        # Instantiate concrete algorithm implementation
        # ---------------------------------------------------------------------
        try:
            self.impl = algo_cls(policy, **self._algo_kwargs, **kwargs)
        except TypeError:
            # Backward compatibility for algorithms without **kwargs support
            self.impl = algo_cls(policy)

        # Keep the resolved policy (if the implementation exposes one)
        self.policy = getattr(self.impl, "policy", self.policy)

        logger.debug(
            "Algorithm initialized: variant=%s, pepper_pre=%s, algo_kwargs=%s",
            self.variant,
            bool(self._prehash),
            bool(self._algo_kwargs),
        )

    # -------------------------------------------------------------------------
    # Internal helpers
    # -------------------------------------------------------------------------

    def _apply_pepper(self, password: str) -> str:
        """Apply any configured prehash pipeline (HMAC, interleave, etc.)."""
        if not password:
            raise HashingError("Password cannot be empty.")
        if self._prehash:
            return self._prehash(password)
        return password

    def _hash_delegate(self, peppered: str) -> str:
        """Delegate the actual hashing to the implementation."""
        if hasattr(self.impl, "hash_raw"):
            return self.impl.hash_raw(peppered)
        # Backward-compatible fallback
        return self.impl.hash(peppered)  # type: ignore[attr-defined]

    def _verify_delegate(self, stored_hash: str, peppered: str) -> bool:
        """Delegate verification to the implementation, with variant safety checks."""
        try:
            if hasattr(self.impl, "verify_raw"):
                return self.impl.verify_raw(stored_hash, peppered)
            return self.impl.verify(stored_hash, peppered)  # type: ignore[attr-defined]
        except Exception:
            # If the hash clearly belongs to another algorithm, return False (no exception)
            if is_foreign_variant(stored_hash, self.variant):
                return False
            raise

    # -------------------------------------------------------------------------
    # Public façade
    # -------------------------------------------------------------------------

    def hash(self, password: str) -> str:
        """
        Hash a password using the configured variant and pepper strategy.
        """
        try:
            pw = self._apply_pepper(password)
            return self._hash_delegate(pw)
        except Exception as e:
            raise HashingError(f"Failed to hash password with {self.variant}: {e}") from e

    def verify(self, stored_hash: str, password: str) -> bool:
        """
        Verify a password against a stored hash using the configured variant and pepper plan.
        """
        try:
            pw = self._apply_pepper(password)
            return self._verify_delegate(stored_hash, pw)
        except Exception as e:
            raise VerificationError(f"Failed to verify password with {self.variant}: {e}") from e

    def needs_rehash(self, stored_hash: str) -> bool:
        """
        Return True if the stored hash is outdated per the current policy parameters.
        """
        if not hasattr(self.impl, "needs_rehash"):
            return False
        try:
            return self.impl.needs_rehash(stored_hash)
        except Exception as e:
            logger.error("needs_rehash failed for %s: %s", self.variant, e)
            return False

    def get_policy_dict(self) -> dict[str, Any]:
        """
        Return the policy as a plain dict if the implementation exposes it.
        """
        if self.policy and hasattr(self.policy, "to_dict"):
            return self.policy.to_dict()  # type: ignore[no-any-return]
        return {}

    def __call__(self, password: str) -> str:
        """
        Shortcut for Algorithm(password) → hash(password)
        """
        return self.hash(password)
