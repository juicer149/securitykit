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
from securitykit.transform.pepper import apply_pepper
from securitykit.hashing.utils import is_foreign_variant


class Algorithm:
    """
    Uniform façade over a concrete hashing algorithm implementation.

    Responsibilities:
      - Resolve variant class
      - Apply pepper (PEPPER_* config) exactly once
      - Delegate to implementation's raw methods
      - Provide needs_rehash passthrough
    """

    def __init__(
        self,
        variant: str,
        policy: Any = None,
        *,
        config: Mapping[str, Any] | None = None,
        **kwargs: Any,
    ):
        v = variant.lower()
        try:
            algo_cls = get_algorithm_class(v)
        except UnknownAlgorithmError as e:
            # Helpful install hints when using minimal core + extras
            hints = {
                "argon2": "Install extra: pip install 'securitykit[alg_argon2]'",
                "bcrypt": "Install extra: pip install 'securitykit[alg_bcrypt]'",
                "werkzeug_pbkdf2": "Install extra: pip install 'securitykit[alg_werkzeug]'",
            }
            hint = f" {hints[v]}" if v in hints else ""
            raise UnknownAlgorithmError(str(e) + hint) from e

        self._config = config or os.environ
        params: dict[str, Any] = {}
        # Pass policy through; do NOT pass pepper (all pepper centralized)
        self.impl = algo_cls(policy, **params, **kwargs)
        self.variant = v
        self.policy = getattr(self.impl, "policy", None)
        logger.debug("Algorithm initialized variant=%s", self.variant)

    # ---- internal helpers -------------------------------------------------

    def _pepper(self, password: str) -> str:
        return apply_pepper(password, self._config)

    def _hash_delegate(self, peppered: str) -> str:
        # Preferred path: hash_raw present
        if hasattr(self.impl, "hash_raw"):
            return self.impl.hash_raw(peppered)  # type: ignore[attr-defined]
        # Fallback legacy path: assume 'hash' expects already-prepared input
        return self.impl.hash(peppered)  # type: ignore[no-any-return]

    def _verify_delegate(self, stored_hash: str, peppered: str) -> bool:
        try:
            if hasattr(self.impl, "verify_raw"):
                return self.impl.verify_raw(stored_hash, peppered)  # type: ignore[attr-defined]
            return self.impl.verify(stored_hash, peppered)  # type: ignore[no-any-return]
        except Exception:
            # Central cross-variant tolerance:
            # If the stored hash looks like another algorithm, treat as a non-match (False)
            # instead of propagating an exception from the underlying lib.
            if is_foreign_variant(stored_hash, self.variant):
                return False
            # Same-variant but error (e.g., corrupt hash) -> let outer layer wrap as VerificationError
            raise

    # ---- public façade ----------------------------------------------------

    def hash(self, password: str) -> str:
        try:
            if not password:
                raise HashingError("Password cannot be empty")
            peppered = self._pepper(password)
            return self._hash_delegate(peppered)
        except HashingError:
            raise
        except Exception as e:
            raise HashingError(f"Failed to hash password with {self.variant}: {e}") from e

    def verify(self, stored_hash: str, password: str) -> bool:
        try:
            if not stored_hash or not password:
                return False
            peppered = self._pepper(password)
            return self._verify_delegate(stored_hash, peppered)
        except VerificationError:
            raise
        except Exception as e:
            raise VerificationError(
                f"Failed to verify password with {self.variant}: {e}"
            ) from e

    def needs_rehash(self, stored_hash: str) -> bool:
        if not hasattr(self.impl, "needs_rehash"):
            return False
        try:
            return self.impl.needs_rehash(stored_hash)  # type: ignore[no-any-return]
        except Exception as e:
            logger.error("needs_rehash failed for %s: %s", self.variant, e)
            return False

    def get_policy_dict(self) -> dict[str, Any]:
        if self.policy and hasattr(self.policy, "to_dict"):
            return self.policy.to_dict()  # type: ignore[no-any-return]
        return {}

    def __call__(self, password: str) -> str:
        return self.hash(password)
