"""
securitykit.hashing.algorithms.argon2
-------------------------------------

Argon2 password hashing implementation using argon2-cffi.

This version:
  • Delegates capability detection to Argon2Policy (diagnostics-driven)
  • Uses supports_internal_pepper to decide whether to use native `secret`
  • Compatible with SecurityKit’s unified PepperFactory
"""

from __future__ import annotations
from typing import Optional, ClassVar, Type

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy
from securitykit.exceptions import HashingError
from securitykit.logging_config import logger

try:
    from argon2 import PasswordHasher, exceptions as a2_exc
except ImportError as e:
    raise HashingError(
        "argon2-cffi is required but not installed. "
        "Install it via: pip install 'argon2-cffi>=21.3.0'"
    ) from e


@register_algorithm("argon2")
class Argon2:
    """
    Argon2 password hashing algorithm.

    Behavior:
      - Reads Argon2Policy for cost parameters and diagnostic flags.
      - If `supports_internal_pepper=True` and a `secret` is provided,
        uses Argon2’s native keyed mode.
      - Otherwise runs normally without `secret` (peppering handled externally).
    """

    DEFAULT_POLICY_CLS: ClassVar[Type[Argon2Policy]] = Argon2Policy

    def __init__(self, policy: Optional[Argon2Policy] = None, secret: Optional[bytes] = None):
        # ------------------------------------------------------------------
        # Load policy (includes diagnostic info)
        # ------------------------------------------------------------------
        policy = policy or Argon2Policy()
        if not isinstance(policy, Argon2Policy):
            raise TypeError("policy must be an instance of Argon2Policy")

        self.policy = policy
        self.secret = secret

        # ------------------------------------------------------------------
        # Prepare construction parameters
        # ------------------------------------------------------------------
        kwargs = dict(
            time_cost=policy.time_cost,  # type: ignore[arg-type] 
            memory_cost=policy.memory_cost,  # type: ignore[arg-type]
            parallelism=policy.parallelism,  # type: ignore[arg-type]
            hash_len=policy.hash_length,  # type: ignore[arg-type]
            salt_len=policy.salt_length,  # type: ignore[arg-type]
        )

        # Only include secret if supported
        if secret and policy.supports_internal_pepper:  #type: ignore[attr-defined]
            kwargs["secret"] = secret
            logger.debug(
                "Initializing Argon2 with native secret (argon2-cffi %s)",
                policy.version,  # type: ignore[attr-defined]
            )
        elif secret and not policy.supports_internal_pepper:  #type: ignore[attr-defined]
            logger.warning(
                "Argon2 'secret' not supported in argon2-cffi %s. "
                "Ignoring secret (peppering handled externally).",
                policy.version,  # type: ignore[attr-defined]
            )

        try:
            self._ph = PasswordHasher(**kwargs)
        except TypeError as exc:
            raise HashingError(
                f"Argon2 configuration error: {exc}. "
                f"Ensure argon2-cffi >= 21.3.0 for full secret support."
            ) from exc
        except Exception as e:
            raise HashingError(f"Failed to initialize Argon2: {e}") from e

    # ------------------------------------------------------------------
    # Core API
    # ------------------------------------------------------------------

    def hash_raw(self, password: str) -> str:
        if not password:
            raise HashingError("Password cannot be empty.")
        try:
            return self._ph.hash(password)
        except Exception as e:
            raise HashingError(f"Argon2 hashing failed: {e}") from e

    def verify_raw(self, stored_hash: str, password: str) -> bool:
        if not stored_hash or not password:
            return False
        try:
            return self._ph.verify(stored_hash, password)
        except Exception as e:
            if a2_exc and isinstance(e, getattr(a2_exc, "VerifyMismatchError", Exception)):
                return False
            raise HashingError(f"Argon2 verification failed: {e}") from e

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            return self._ph.check_needs_rehash(stored_hash)
        except Exception:
            return False
