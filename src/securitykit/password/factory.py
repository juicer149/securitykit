# securitykit/password/factory.py
from typing import Any, Mapping

from securitykit.utils.config_loader import ConfigLoader
from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator


class PasswordFactory:
    """
    Factory for constructing password policy + validator from config.
    Independent of hashing.
    """

    def __init__(self, config: Mapping[str, Any]):
        self.config = config
        self.loader = ConfigLoader(config)

    def get_policy(self) -> PasswordPolicy:
        """Build PasswordPolicy from config."""
        return self.loader.build(
            PasswordPolicy,
            prefix="PASSWORD_",
            name="PasswordPolicy",
        )

    def get_validator(self) -> PasswordValidator:
        """Return a PasswordValidator for enforcing the policy."""
        return PasswordValidator(self.get_policy())
