from __future__ import annotations

from typing import ClassVar

try:
    import bcrypt  # type: ignore[reportMissingImports]
    _BC_AVAILABLE = True
except Exception:
    bcrypt = None  # type: ignore[assignment]
    _BC_AVAILABLE = False

from importlib.metadata import version as _dist_version, PackageNotFoundError  # NEW

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.bcrypt import BcryptPolicy
from securitykit.exceptions import HashingError
from securitykit.hashing.capabilities import CapabilityInfo


def get_bcrypt_diagnostics() -> CapabilityInfo:
    """
    Return diagnostics for bcrypt backend.
    """
    try:
        # Prefer package metadata
        try:
            ver = _dist_version("bcrypt")
        except PackageNotFoundError:
            # Fallbacks on older wheels
            ver = getattr(getattr(bcrypt, "__about__", None), "__version__", None) or getattr(bcrypt, "__version__", "unknown")
        return CapabilityInfo(available=True, version=ver, extra={"supports_secret": False})
    except Exception:
        return CapabilityInfo(available=False, version="unknown", extra={"supports_secret": False})


if _BC_AVAILABLE:

    @register_algorithm("bcrypt")
    class Bcrypt:
        """
        Bcrypt implementation expecting already peppered password input in hash_raw/verify_raw.
        - verify_raw returns bool for valid bcrypt hashes; invalid/foreign formats raise,
          and the central Algorithm decides cross-variant behavior.
        """
        DEFAULT_POLICY_CLS: ClassVar[type[BcryptPolicy]] = BcryptPolicy

        def __init__(self, policy: BcryptPolicy | None = None):
            policy = policy or BcryptPolicy()
            if not isinstance(policy, BcryptPolicy):
                raise TypeError("policy must be BcryptPolicy")
            self.policy = policy

        def hash_raw(self, peppered_password: str) -> str:
            if not peppered_password:
                raise HashingError("Password cannot be empty")
            try:
                return bcrypt.hashpw(  # type: ignore[arg-type]
                    peppered_password.encode("utf-8"),
                    bcrypt.gensalt(rounds=self.policy.rounds),  # type: ignore[arg-type]
                ).decode("utf-8")
            except Exception as e:
                raise HashingError(f"Bcrypt hash failed: {e}") from e

        def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
            if not stored_hash or not peppered_password:
                return False
            # For non-bcrypt or malformed input bcrypt.checkpw may raise ValueError.
            # We let exceptions bubble; Algorithm handles cross-variant tolerance.
            return bcrypt.checkpw(  # type: ignore[arg-type]
                peppered_password.encode("utf-8"),
                stored_hash.encode("utf-8"),
            )

        def needs_rehash(self, stored_hash: str) -> bool:
            try:
                # $2b$12$... -> parts[2] = "12"
                parts = stored_hash.split("$")
                cost = int(parts[2])
                return cost < self.policy.rounds
            except Exception:
                return False
