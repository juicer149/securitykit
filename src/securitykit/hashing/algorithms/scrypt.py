from __future__ import annotations

import base64
import hashlib
import hmac
import math
import os
from typing import ClassVar, Tuple

from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.scrypt import ScryptPolicy
from securitykit.exceptions import HashingError


@register_algorithm("scrypt")
class Scrypt:
    """
    Scrypt implementation using hashlib.scrypt.

    Encoded format (custom):
      $scrypt$ln=<logN>,r=<r>,p=<p>$<salt_b64>$<hash_b64>

    Cross-variant behavior is centralized in Algorithm; here we raise on non-scrypt inputs
    and let the façade decide whether to return False (foreign) or bubble errors.
    """

    DEFAULT_POLICY_CLS: ClassVar[type[ScryptPolicy]] = ScryptPolicy

    def __init__(self, policy: ScryptPolicy | None = None):
        policy = policy or ScryptPolicy()
        if not isinstance(policy, ScryptPolicy):
            raise TypeError("policy must be ScryptPolicy")
        self.policy = policy
        # Allow overriding OpenSSL maxmem via env; default generous to avoid false limits.
        self._maxmem = int(os.environ.get("SCRYPT_MAXMEM", 512 * 1024 * 1024))

    @staticmethod
    def _encode(ln: int, r: int, p: int, salt: bytes, dk: bytes) -> str:
        return (
            f"$scrypt$ln={ln},r={r},p={p}$"
            f"{base64.b64encode(salt).decode('ascii')}$"
            f"{base64.b64encode(dk).decode('ascii')}"
        )

    @staticmethod
    def _decode(encoded: str) -> Tuple[int, int, int, bytes, bytes]:
        if not encoded.startswith("$scrypt$"):
            raise ValueError("not a scrypt hash")
        try:
            _, _alg, params, salt_b64, dk_b64 = encoded.split("$", 4)
            ln = r = p = None  # type: ignore[assignment]
            for kv in params.split(","):
                k, v = kv.split("=", 1)
                if k == "ln":
                    ln = int(v)
                elif k == "r":
                    r = int(v)
                elif k == "p":
                    p = int(v)
            if ln is None or r is None or p is None:
                raise ValueError("missing scrypt parameters")
            salt = base64.b64decode(salt_b64)
            dk = base64.b64decode(dk_b64)
            return ln, r, p, salt, dk
        except Exception as e:
            raise ValueError(f"invalid scrypt format: {e}") from e

    def hash_raw(self, peppered_password: str) -> str:
        if not peppered_password:
            raise HashingError("Password cannot be empty")
        ln = int(math.log2(self.policy.n))
        salt = os.urandom(self.policy.salt_length)
        try:
            dk = hashlib.scrypt(
                peppered_password.encode("utf-8"),
                salt=salt,
                n=self.policy.n,
                r=self.policy.r,
                p=self.policy.p,
                dklen=self.policy.hash_length,
                maxmem=self._maxmem,
            )
        except Exception as e:
            raise HashingError(f"scrypt hash failed: {e}") from e
        return self._encode(ln, self.policy.r, self.policy.p, salt, dk)

    def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
        if not stored_hash or not peppered_password:
            return False
        ln, r, p, salt, dk_stored = self._decode(stored_hash)  # may raise ValueError for foreign/malformed
        dk = hashlib.scrypt(
            peppered_password.encode("utf-8"),
            salt=salt,
            n=2**ln,
            r=r,
            p=p,
            dklen=len(dk_stored),
            maxmem=self._maxmem,
        )
        return hmac.compare_digest(dk, dk_stored)

    def needs_rehash(self, stored_hash: str) -> bool:
        try:
            ln, r, p, _salt, dk = self._decode(stored_hash)
            policy_logn = int(math.log2(self.policy.n))
            if policy_logn > ln or self.policy.r > r or self.policy.p > p:
                return True
            if self.policy.hash_length > len(dk):
                return True
            return False
        except Exception:
            return False
