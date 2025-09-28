# securitykit/policies/argon2.py
from dataclasses import dataclass

from securitykit.core.policy_registry import register_policy
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger

# --- Technical minimums (hard lower bounds) ---
ARGON2_MIN_TIME_COST = 1
ARGON2_MIN_MEMORY = 8 * 1024        # 8 MiB
ARGON2_MIN_PARALLELISM = 1
ARGON2_MIN_HASH_LENGTH = 16
ARGON2_MIN_SALT_LENGTH = 16

# --- Recommended baselines (OWASP / community) ---
ARGON2_RECOMMENDED_TIME_COST = 2
ARGON2_RECOMMENDED_MEMORY = 64 * 1024    # 64 MiB
ARGON2_RECOMMENDED_PARALLELISM = 1
ARGON2_RECOMMENDED_HASH_LENGTH = 32
# Recommended salt length is typically 16 bytes, so reuse ARGON2_MIN_SALT_LENGTH

# --- Upper limits (warnings only) ---
ARGON2_MAX_TIME_COST = 6          # above this = performance / DoS risk
ARGON2_MAX_MEMORY = 256 * 1024    # 256 MiB = unusually high for web apps
ARGON2_MAX_PARALLELISM = 4        # >4 can cause resource strain


@register_policy("argon2")
@dataclass
class Argon2Policy:
    """Configuration policy for Argon2 password hashing."""

    time_cost: int = ARGON2_RECOMMENDED_TIME_COST
    memory_cost: int = ARGON2_RECOMMENDED_MEMORY
    parallelism: int = ARGON2_RECOMMENDED_PARALLELISM
    hash_length: int = ARGON2_RECOMMENDED_HASH_LENGTH
    salt_length: int = ARGON2_MIN_SALT_LENGTH

    def __post_init__(self):
        # --- Hard checks ---
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

        # --- Warnings: below recommended baselines ---
        if self.time_cost < ARGON2_RECOMMENDED_TIME_COST:
            logger.warning("Argon2 time_cost %d below recommended baseline (%d).",
                           self.time_cost, ARGON2_RECOMMENDED_TIME_COST)

        if self.memory_cost < ARGON2_RECOMMENDED_MEMORY:
            logger.warning("Argon2 memory_cost %d KiB below recommended baseline (%d KiB).",
                           self.memory_cost, ARGON2_RECOMMENDED_MEMORY)

        if self.parallelism <= ARGON2_RECOMMENDED_PARALLELISM:
            logger.warning("Argon2 parallelism %d at or below recommended baseline (%d).",
                           self.parallelism, ARGON2_RECOMMENDED_PARALLELISM)

        if self.hash_length < ARGON2_RECOMMENDED_HASH_LENGTH:
            logger.warning("Argon2 hash_length %d below recommended baseline (%d).",
                           self.hash_length, ARGON2_RECOMMENDED_HASH_LENGTH)

        # --- Warnings: above safe ranges ---
        if self.time_cost > ARGON2_MAX_TIME_COST:
            logger.warning("Argon2 time_cost %d is very high (> %d).",
                           self.time_cost, ARGON2_MAX_TIME_COST)

        if self.memory_cost > ARGON2_MAX_MEMORY:
            logger.warning("Argon2 memory_cost %d KiB is extremely high (> %d KiB).",
                           self.memory_cost, ARGON2_MAX_MEMORY)

        if self.parallelism > ARGON2_MAX_PARALLELISM:
            logger.warning("Argon2 parallelism %d unusually high (> %d).",
                           self.parallelism, ARGON2_MAX_PARALLELISM)

