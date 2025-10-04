from dataclasses import dataclass, asdict
from typing import Any, ClassVar
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger
from securitykit.password.defaults import (
    PASSWORD_MIN_LENGTH,
    PASSWORD_MAX_LENGTH,
    PASSWORD_RECOMMENDED_MIN_LENGTH,
    PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH,
    DEFAULT_MIN_LENGTH,
    DEFAULT_REQUIRE_UPPER,
    DEFAULT_REQUIRE_LOWER,
    DEFAULT_REQUIRE_DIGIT,
    DEFAULT_REQUIRE_SPECIAL,
    DEFAULT_COMPLEXITY_RULE,
    DEFAULT_COMPLEXITY_MIN_LENGTH,
)


@dataclass
class PasswordPolicy:
    """
    Defines both *hard enforcement rules* (length, required chars)
    and *soft complexity thresholds* for strength evaluation.
    """

    # Hard constraints
    PASSWORD_MIN_LENGTH: ClassVar[int] = PASSWORD_MIN_LENGTH
    PASSWORD_MAX_LENGTH: ClassVar[int] = PASSWORD_MAX_LENGTH
    PASSWORD_RECOMMENDED_MIN_LENGTH: ClassVar[int] = PASSWORD_RECOMMENDED_MIN_LENGTH
    PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH: ClassVar[int] = PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH

    # Core configuration
    min_length: int = DEFAULT_MIN_LENGTH
    require_upper: bool = DEFAULT_REQUIRE_UPPER
    require_lower: bool = DEFAULT_REQUIRE_LOWER
    require_digit: bool = DEFAULT_REQUIRE_DIGIT
    require_special: bool = DEFAULT_REQUIRE_SPECIAL

    # Soft complexity (scoring layer)
    # Note: complexity_min_length is a SOFT threshold and may be >= min_length.
    complexity_rule: int = DEFAULT_COMPLEXITY_RULE     # min number of rules (1–5)
    complexity_min_length: int = DEFAULT_COMPLEXITY_MIN_LENGTH  # contributes to strength score

    def to_dict(self) -> dict[str, Any]:
        """Return a serializable dict representation."""
        return asdict(self)

    def __post_init__(self):
        # --- Hard bounds ---
        if self.min_length < self.PASSWORD_MIN_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be at least {self.PASSWORD_MIN_LENGTH}"
            )
        if self.min_length > self.PASSWORD_MAX_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be <= {self.PASSWORD_MAX_LENGTH}"
            )

        # --- Warnings for misconfigurations ---
        if self.min_length < self.PASSWORD_RECOMMENDED_MIN_LENGTH:
            logger.warning(
                "Password min_length %d is below recommended minimum (%d).",
                self.min_length,
                self.PASSWORD_RECOMMENDED_MIN_LENGTH,
            )
        if self.min_length > self.PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH:
            logger.warning(
                "Password min_length %d is unusually high (> %d). Ensure this is intentional.",
                self.min_length,
                self.PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH,
            )

        # --- Validate soft complexity parameters ---
        if not (1 <= self.complexity_rule <= 5):
            raise InvalidPolicyConfig(
                "PASSWORD_COMPLEXITY_RULE must be between 1 and 5."
            )
        if self.complexity_min_length < 0:
            raise InvalidPolicyConfig(
                "PASSWORD_COMPLEXITY_MIN_LENGTH must be >= 0."
            )

        # --- Warnings for soft complexity misconfigurations ---
        # If the soft length threshold is below the hard minimum, it never affects scoring.
        # This is harmless but likely unintended/redundant.
        if self.complexity_min_length < self.min_length:
            logger.warning(
                "PASSWORD_COMPLEXITY_MIN_LENGTH (%d) is less than min_length (%d): "
                "this soft rule is redundant and will never influence strength scoring. "
                "Consider setting it to at least min_length.",
                self.complexity_min_length,
                self.min_length,
            )
