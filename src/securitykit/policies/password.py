# securitykit/policies/password.py
from dataclasses import dataclass
import re 

from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger


@dataclass
class PasswordPolicy:
    min_length: int = 8
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True

    def __post_init__(self):
        if self.min_length < 1:
            raise InvalidPolicyConfig("Password min_length must be at least 1")
        if self.min_length > 128:
            logger.warning(
                "Password min_length %d is unusually high (>128). Ensure this is intentional.",
                self.min_length,
            )
        if self.min_length < 12:
            logger.warning(
                "Password min_length %d is below recommended minimum (12).", self.min_length
            )

    def validate(self, password: str) -> None:
        if len(password) < self.min_length:
            raise InvalidPolicyConfig(
                f"Password must be at least {self.min_length} characters long."
            )
        if self.require_upper and not re.search(r"[A-Z]", password):
            raise InvalidPolicyConfig("Password must contain at least one uppercase letter.")
        if self.require_lower and not re.search(r"[a-z]", password):
            raise InvalidPolicyConfig("Password must contain at least one lowercase letter.")
        if self.require_digit and not re.search(r"\d", password):
            raise InvalidPolicyConfig("Password must contain at least one digit.")
        if self.require_special and not re.search(r"[^A-Za-z0-9]", password):
            raise InvalidPolicyConfig("Password must contain at least one special character.")
