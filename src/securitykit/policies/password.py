# securitykit/policies/password.py
from dataclasses import dataclass, asdict
from typing import Any, ClassVar
import re

from securitykit.core.interfaces import PolicyProtocol
from securitykit.exceptions import InvalidPolicyConfig
from securitykit.logging_config import logger

# ==========================
# Password Policy Constants
# ==========================
PASSWORD_MIN_LENGTH = 1
PASSWORD_MAX_LENGTH = 4096
PASSWORD_RECOMMENDED_MIN_LENGTH = 12


@dataclass
class PasswordPolicy(PolicyProtocol):
    """
    Password policy for enforcing complexity rules.

    Defaults are intentionally modest (min_length=8), while constants above
    define hard lower/upper bounds and OWASP-recommended minimums.
    """

    min_length: int = 8
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True

    # Empty schema since this policy is not benchmarked
    BENCH_SCHEMA: ClassVar[dict[str, list[int]]] = {}

    def to_dict(self) -> dict[str, Any]:
        """Return current policy config as a dict."""
        return asdict(self)

    def __post_init__(self):
        # Validate min_length boundaries
        if self.min_length < PASSWORD_MIN_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be at least {PASSWORD_MIN_LENGTH}"
            )
        if self.min_length > PASSWORD_MAX_LENGTH:
            raise InvalidPolicyConfig(
                f"Password min_length must be <= {PASSWORD_MAX_LENGTH}"
            )

        # Log warnings for unusual values
        if self.min_length < PASSWORD_RECOMMENDED_MIN_LENGTH:
            logger.warning(
                "Password min_length %d is below recommended minimum (%d).",
                self.min_length,
                PASSWORD_RECOMMENDED_MIN_LENGTH,
            )
        if self.min_length > 128:
            logger.warning(
                "Password min_length %d is unusually high (>128). Ensure this is intentional.",
                self.min_length,
            )

    def validate(self, password: str) -> None:
        """
        Validate that a password satisfies the configured policy.

        Raises:
            InvalidPolicyConfig: if the password violates policy requirements.
        """
        if len(password) < self.min_length:
            raise InvalidPolicyConfig(
                f"Password must be at least {self.min_length} characters long."
            )
        if len(password) > PASSWORD_MAX_LENGTH:
            raise InvalidPolicyConfig(
                f"Password is too long (max {PASSWORD_MAX_LENGTH} characters)."
            )
        if self.require_upper and not re.search(r"[A-Z]", password):
            raise InvalidPolicyConfig("Password must contain at least one uppercase letter.")
        if self.require_lower and not re.search(r"[a-z]", password):
            raise InvalidPolicyConfig("Password must contain at least one lowercase letter.")
        if self.require_digit and not re.search(r"\d", password):
            raise InvalidPolicyConfig("Password must contain at least one digit.")
        if self.require_special and not re.search(r"[^A-Za-z0-9]", password):
            raise InvalidPolicyConfig("Password must contain at least one special character.")
