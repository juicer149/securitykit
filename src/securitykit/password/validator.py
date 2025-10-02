# securitykit/password/validator.py
import re
from securitykit.password.policy import PasswordPolicy
from securitykit.exceptions import InvalidPolicyConfig


class PasswordValidator:
    """
    Enforces password complexity rules based on a given PasswordPolicy.
    """

    def __init__(self, policy: PasswordPolicy):
        self.policy = policy

    def validate(self, password: str) -> None:
        """Raise InvalidPolicyConfig if the password violates the policy."""

        if len(password) < self.policy.min_length:
            raise InvalidPolicyConfig(
                f"Password must be at least {self.policy.min_length} characters long."
            )
        if len(password) > self.policy.PASSWORD_MAX_LENGTH:
            raise InvalidPolicyConfig(
                f"Password too long (max {self.policy.PASSWORD_MAX_LENGTH} characters)."
            )

        if self.policy.require_upper and not re.search(r"[A-Z]", password):
            raise InvalidPolicyConfig("Password must contain at least one uppercase letter.")
        if self.policy.require_lower and not re.search(r"[a-z]", password):
            raise InvalidPolicyConfig("Password must contain at least one lowercase letter.")
        if self.policy.require_digit and not re.search(r"\d", password):
            raise InvalidPolicyConfig("Password must contain at least one digit.")
        if self.policy.require_special and not re.search(r"[^A-Za-z0-9]", password):
            raise InvalidPolicyConfig("Password must contain at least one special character.")
