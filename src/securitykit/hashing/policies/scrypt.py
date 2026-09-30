from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import ClassVar, Any
import math

from securitykit.hashing.policy_registry import register_policy
from securitykit.hashing.interfaces import BenchValue
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger


# OWASP Password Storage Cheat Sheet: N=2**17, r=8, p=1 (about 128 MiB).
# Values below the recommendation are allowed (tests and small hosts)
# but logged as a warning.
_SCRYPT_MIN_LOGN = 12   # 2**12, hard floor for anything sensible
_SCRYPT_RECOMMENDED_LOGN = 17  # 2**17, OWASP recommendation
_SCRYPT_MAX_LOGN = 20   # 2**20

@dataclass(frozen=True)
@register_policy("scrypt")
class ScryptPolicy:
    """
    Scrypt policy (hashlib.scrypt).
    """
    ENV_PREFIX: ClassVar[str] = "SCRYPT_"
    BENCH_SCHEMA: ClassVar[dict[str, list[BenchValue]]] = {
        # Candidates around the OWASP recommendation. 2**17 needs about
        # 128 MiB, within the default SCRYPT_MAXMEM of 512 MiB.
        "n": [2**15, 2**16, 2**17],
        "r": [8],
        "p": [1, 2],
    }

    n: int = 2**_SCRYPT_RECOMMENDED_LOGN
    r: int = 8
    p: int = 1
    salt_length: int = 16
    hash_length: int = 32

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __post_init__(self) -> None:
        if self.n <= 0 or self.n & (self.n - 1) != 0:
            raise InvalidPolicyConfig("scrypt 'n' must be a power of two (e.g., 16384).")
        logn = int(math.log2(self.n))
        if logn < _SCRYPT_RECOMMENDED_LOGN:
            logger.warning(
                "scrypt n=%d (2**%d) is below the OWASP recommendation (2**%d).",
                self.n, logn, _SCRYPT_RECOMMENDED_LOGN,
            )
        if logn > _SCRYPT_MAX_LOGN:
            logger.warning("scrypt n=%d (2**%d) unusually high (> 2**%d).", self.n, logn, _SCRYPT_MAX_LOGN)
        if self.r <= 0:
            raise InvalidPolicyConfig("scrypt 'r' must be > 0.")
        if self.p <= 0:
            raise InvalidPolicyConfig("scrypt 'p' must be > 0.")
        if self.salt_length < 8:
            logger.warning("scrypt salt_length=%d is small (< 8).", self.salt_length)
        if self.hash_length < 16:
            logger.warning("scrypt hash_length=%d is small (< 16).", self.hash_length)
