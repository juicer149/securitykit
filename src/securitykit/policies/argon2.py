# securitykit/policies/argon2.py
from dataclasses import dataclass
import logging

from securitykit.core.policy_registry import register_policy
from securitykit.exceptions import InvalidPolicyConfig

logger = logging.getLogger(__name__)

# Argon2 constants
ARGON2_MIN_TIME_COST = 1
ARGON2_MAX_TIME_COST = 20

ARGON2_MIN_MEMORY = 65536
ARGON2_WARN_MEMORY = 131072
ARGON2_MAX_MEMORY = 1048576

ARGON2_MIN_PARALLELISM = 1
ARGON2_MAX_PARALLELISM = 64

ARGON2_MIN_HASH_LENGTH = 16
ARGON2_WARN_HASH_LENGTH = 32

ARGON2_MIN_SALT_LENGTH = 16
ARGON2_MIN_PEPPER_LENGTH = 16


@register_policy("argon2")
@dataclass
class Argon2Policy:
    time_cost: int = 6
    memory_cost: int = 102400  # KiB
    parallelism: int = 4
    hash_length: int = 32
    salt_length: int = 16
    pepper: str | None = None

    def __post_init__(self):
        # Hard checks
        if self.time_cost < ARGON2_MIN_TIME_COST:
            raise InvalidPolicyConfig(f"Argon2 time_cost must be >= {ARGON2_MIN_TIME_COST}")
        if self.parallelism < ARGON2_MIN_PARALLELISM:
            raise InvalidPolicyConfig(f"Argon2 parallelism must be >= {ARGON2_MIN_PARALLELISM}")
        if self.hash_length < ARGON2_MIN_HASH_LENGTH:
            raise InvalidPolicyConfig(f"Argon2 hash_length must be >= {ARGON2_MIN_HASH_LENGTH}")
        if self.salt_length < ARGON2_MIN_SALT_LENGTH:
            raise InvalidPolicyConfig(f"Argon2 salt_length must be >= {ARGON2_MIN_SALT_LENGTH}")

        # Warnings
        if self.memory_cost < ARGON2_MIN_MEMORY:
            logger.warning("Argon2 memory_cost %d is below recommended minimum (%d).",
                           self.memory_cost, ARGON2_MIN_MEMORY)
        if self.memory_cost < ARGON2_WARN_MEMORY:
            logger.warning("Argon2 memory_cost %d is below OWASP recommended baseline (%d).",
                           self.memory_cost, ARGON2_WARN_MEMORY)
        if self.hash_length < ARGON2_WARN_HASH_LENGTH:
            logger.warning("Argon2 hash_length %d is below OWASP recommended baseline (%d).",
                           self.hash_length, ARGON2_WARN_HASH_LENGTH)

        if self.time_cost > ARGON2_MAX_TIME_COST:
            logger.warning("Argon2 time_cost %d is very high (> %d).",
                           self.time_cost, ARGON2_MAX_TIME_COST)
        if self.memory_cost > ARGON2_MAX_MEMORY:
            logger.warning("Argon2 memory_cost %d is extremely high (> %d).",
                           self.memory_cost, ARGON2_MAX_MEMORY)
        if self.parallelism > ARGON2_MAX_PARALLELISM:
            logger.warning("Argon2 parallelism %d is unusually high (> %d).",
                           self.parallelism, ARGON2_MAX_PARALLELISM)

        # Pepper
        if self.pepper is not None and not isinstance(self.pepper, str):
            raise InvalidPolicyConfig("Argon2 pepper must be a string if provided")
        if self.pepper and len(self.pepper) < ARGON2_MIN_PEPPER_LENGTH:
            logger.warning("Argon2 pepper is shorter than %d characters.",
                           ARGON2_MIN_PEPPER_LENGTH)
        if not self.pepper:
            logger.info("No pepper configured for Argon2 (optional but recommended).")
