# securitykit/password/policy.py
from dataclasses import dataclass, asdict
from typing import Any, ClassVar
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger


@dataclass
class PasswordPolicy:
    """
    Password policy definition.
    Holds configuration + static validation of parameters.
    Does NOT validate actual passwords (see PasswordValidator).
    """

    PASSWORD_MIN_LENGTH: ClassVar[int] = 1
    PASSWORD_MAX_LENGTH: ClassVar[int] = 4096
    PASSWORD_RECOMMENDED_MIN_LENGTH: ClassVar[int] = 12
    PASSWORD_UNUSUALLY_HIGH_MIN_LENGTH: ClassVar[int] = 128

    min_length: int = 8
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def __post_init__(self):
        if self.min_length < self.PASSWORD_MIN_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be at least {self.PASSWORD_MIN_LENGTH}"
            )
        if self.min_length > self.PASSWORD_MAX_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be <= {self.PASSWORD_MAX_LENGTH}"
            )

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
