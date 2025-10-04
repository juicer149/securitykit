from typing import Any, Mapping
from securitykit.utils.config_loader import ConfigLoader
from securitykit.password.policy import PasswordPolicy
from securitykit.password.validator import PasswordValidator
from securitykit.config import PASSWORD_ENV_PREFIX


class PasswordFactory:
    """
    Factory for constructing password policy + validator from environment or dict config.
    Independent from hashing system.
    """

    def __init__(self, config: Mapping[str, Any]):
        self.config = config
        self.loader = ConfigLoader(config)

    def get_policy(self) -> PasswordPolicy:
        """Build and return a PasswordPolicy instance."""
        return self.loader.build(PasswordPolicy, prefix=PASSWORD_ENV_PREFIX, name="PasswordPolicy")

    def get_validator(self) -> PasswordValidator:
        """Return a PasswordValidator enforcing this policy."""
        return PasswordValidator(self.get_policy())
