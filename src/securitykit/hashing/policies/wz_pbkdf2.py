from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Any, ClassVar

from securitykit.hashing.policy_registry import register_policy
from securitykit.hashing.interfaces import BenchValue
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger


@dataclass(frozen=True)
@register_policy("werkzeug_pbkdf2")
class WerkzeugPBKDF2Policy:
    """
    Policy wrapper for Werkzeug's PBKDF2 (werkzeug.security).

    Encodes method and iterations in method string at algorithm level:
      effective method = f"{method}:{iterations}"
    """
    # Keep ENV_PREFIX aligned with variant uppercased + underscore to match your factory behavior
    ENV_PREFIX: ClassVar[str] = "WERKZEUG_PBKDF2_"
    BENCH_SCHEMA: ClassVar[dict[str, list[BenchValue]]] = {
        "iterations": [150_000, 200_000, 260_000, 300_000, 390_000],
    }

    method: str = "pbkdf2:sha256"
    iterations: int = 260_000
    salt_length: int = 16

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __post_init__(self) -> None:
        if not self.method.startswith("pbkdf2:"):
            raise InvalidPolicyConfig("WerkzeugPBKDF2Policy.method must start with 'pbkdf2:'")
        if self.iterations < 100_000:
            logger.warning("Werkzeug PBKDF2 iterations %d are low (< 100k).", self.iterations)
        if self.salt_length < 8:
            logger.warning("Werkzeug PBKDF2 salt_length %d is small (< 8).", self.salt_length)
