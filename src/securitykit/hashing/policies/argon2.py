from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import ClassVar, Any
from securitykit.hashing.policy_registry import register_policy
from securitykit.hashing.interfaces import BenchValue
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger

# Tekniska minimum
ARGON2_MIN_TIME_COST = 1
ARGON2_MIN_MEMORY = 8 * 1024
ARGON2_MIN_PARALLELISM = 1
ARGON2_MIN_HASH_LENGTH = 16
ARGON2_MIN_SALT_LENGTH = 16

# Rekommendationer
ARGON2_RECOMMENDED_TIME_COST = 2
ARGON2_RECOMMENDED_MEMORY = 64 * 1024
ARGON2_RECOMMENDED_PARALLELISM = 1
ARGON2_RECOMMENDED_HASH_LENGTH = 32

# Övre varningsnivåer
ARGON2_MAX_TIME_COST = 6
ARGON2_MAX_MEMORY = 256 * 1024
ARGON2_MAX_PARALLELISM = 4


@register_policy("argon2")
@dataclass(frozen=True)
class Argon2Policy:
    ENV_PREFIX: ClassVar[str] = "ARGON2_"
    BENCH_SCHEMA: ClassVar[dict[str, list[BenchValue]]] = {
        "time_cost":   [1, 2, 3, 4, 5, 6],
        "memory_cost": [8*1024, 16*1024, 32*1024, 64*1024, 128*1024, 256*1024],
        "parallelism": [1, 2, 3, 4],
    }

    time_cost: int = ARGON2_RECOMMENDED_TIME_COST
    memory_cost: int = ARGON2_RECOMMENDED_MEMORY
    parallelism: int = ARGON2_RECOMMENDED_PARALLELISM
    hash_length: int = ARGON2_RECOMMENDED_HASH_LENGTH
    salt_length: int = ARGON2_MIN_SALT_LENGTH

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __post_init__(self):
        # Hard bounds
        if self.time_cost < ARGON2_MIN_TIME_COST:
            raise InvalidPolicyConfig(f"time_cost must be >= {ARGON2_MIN_TIME_COST}")
        if self.memory_cost < ARGON2_MIN_MEMORY:
            raise InvalidPolicyConfig(f"memory_cost must be >= {ARGON2_MIN_MEMORY} KiB")
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            raise InvalidPolicyConfig(f"parallelism must be >= {ARGON2_MIN_PARALLELISM}")
        if self.hash_length < ARGON2_MIN_HASH_LENGTH:
            raise InvalidPolicyConfig(f"hash_length must be >= {ARGON2_MIN_HASH_LENGTH}")
        if self.salt_length < ARGON2_MIN_SALT_LENGTH:
            raise InvalidPolicyConfig(f"salt_length must be >= {ARGON2_MIN_SALT_LENGTH}")

        # Warnings (lågt)
        if self.time_cost < ARGON2_RECOMMENDED_TIME_COST:
            logger.warning("Argon2 time_cost %d below recommended (%d)", self.time_cost, ARGON2_RECOMMENDED_TIME_COST)
        if self.memory_cost < ARGON2_RECOMMENDED_MEMORY:
            logger.warning("Argon2 memory_cost %d below recommended (%d)", self.memory_cost, ARGON2_RECOMMENDED_MEMORY)
        if self.parallelism <= ARGON2_RECOMMENDED_PARALLELISM:
            logger.warning("Argon2 parallelism %d at/below recommended (%d)", self.parallelism, ARGON2_RECOMMENDED_PARALLELISM)
        if self.hash_length < ARGON2_RECOMMENDED_HASH_LENGTH:
            logger.warning("Argon2 hash_length %d below recommended (%d)", self.hash_length, ARGON2_RECOMMENDED_HASH_LENGTH)

        # Warnings (högt)
        if self.time_cost > ARGON2_MAX_TIME_COST:
            logger.warning("Argon2 time_cost %d very high (> %d)", self.time_cost, ARGON2_MAX_TIME_COST)
        if self.memory_cost > ARGON2_MAX_MEMORY:
            logger.warning("Argon2 memory_cost %d very high (> %d)", self.memory_cost, ARGON2_MAX_MEMORY)
        if self.parallelism > ARGON2_MAX_PARALLELISM:
            logger.warning("Argon2 parallelism %d unusually high (> %d)", self.parallelism, ARGON2_MAX_PARALLELISM)
