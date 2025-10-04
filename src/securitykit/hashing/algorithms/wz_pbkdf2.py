from __future__ import annotations

from typing import ClassVar

try:
    from werkzeug.security import generate_password_hash, check_password_hash  # type: ignore[reportMissingImports]
    _WZ_AVAILABLE = True
except Exception:
    generate_password_hash = None  # type: ignore[assignment]
    check_password_hash = None  # type: ignore[assignment]
    _WZ_AVAILABLE = False

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.wz_pbkdf2 import WerkzeugPBKDF2Policy
from securitykit.exceptions import HashingError


if _WZ_AVAILABLE:

    @register_algorithm("werkzeug_pbkdf2")
    class WerkzeugPBKDF2:
        """
        Wrapper around werkzeug.security PBKDF2.

        Encoded by Werkzeug itself, typically:
          pbkdf2:sha256:ITERATIONS$SALT$HASH
        """
        DEFAULT_POLICY_CLS: ClassVar[type[WerkzeugPBKDF2Policy]] = WerkzeugPBKDF2Policy

        def __init__(self, policy: WerkzeugPBKDF2Policy | None = None):
            if policy is None:
                policy = WerkzeugPBKDF2Policy()
            elif not isinstance(policy, WerkzeugPBKDF2Policy):
                raise TypeError("policy must be WerkzeugPBKDF2Policy")
            self.policy: WerkzeugPBKDF2Policy = policy

        def _method_with_iterations(self) -> str:
            return f"{self.policy.method}:{int(self.policy.iterations)}"

        def hash_raw(self, peppered_password: str) -> str:
            if not peppered_password:
                raise HashingError("Password cannot be empty")
            try:
                return generate_password_hash(  # type: ignore[misc]
                    peppered_password,
                    method=self._method_with_iterations(),
                    salt_length=int(self.policy.salt_length),
                )
            except Exception as e:
                raise HashingError(f"Werkzeug PBKDF2 hash failed: {e}") from e

        def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
            if not stored_hash or not peppered_password:
                return False
            # Werkzeug returns False for mismatches/unknown formats; exceptions are rare.
            return check_password_hash(stored_hash, peppered_password)  # type: ignore[misc]

        def needs_rehash(self, stored_hash: str) -> bool:
            try:
                head = stored_hash.split("$", 1)[0]
                parts = head.split(":")
                iters_in_hash = int(parts[-1]) if parts and parts[-1].isdigit() else None
                if iters_in_hash is None:
                    return False
                return int(self.policy.iterations) > iters_in_hash
            except Exception:
                return False
