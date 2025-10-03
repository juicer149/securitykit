from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import ClassVar, Any
from securitykit.hashing.policy_registry import register_policy
from securitykit.hashing.interfaces import BenchValue
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger

BCRYPT_MIN_ROUNDS = 4
BCRYPT_RECOMMENDED_ROUNDS = 12
BCRYPT_MAX_ROUNDS = 18

@register_policy("bcrypt")
@dataclass(frozen=True)
class BcryptPolicy:
    ENV_PREFIX: ClassVar[str] = "BCRYPT_"
    BENCH_SCHEMA: ClassVar[dict[str, list[BenchValue]]] = {
        "rounds": [4, 6, 8, 10, 12, 14, 16, 18]
    }

    rounds: int = BCRYPT_RECOMMENDED_ROUNDS

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __post_init__(self):
        if self.rounds < BCRYPT_MIN_ROUNDS:
            raise InvalidPolicyConfig(f"rounds must be >= {BCRYPT_MIN_ROUNDS}")
        if self.rounds > BCRYPT_MAX_ROUNDS:
            logger.warning("bcrypt rounds %d unusually high (> %d)", self.rounds, BCRYPT_MAX_ROUNDS)
        if self.rounds < BCRYPT_RECOMMENDED_ROUNDS:
            logger.warning("bcrypt rounds %d below recommended (%d)", self.rounds, BCRYPT_RECOMMENDED_ROUNDS)
