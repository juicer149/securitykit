# securitykit/core/factory.py
import inspect
import logging

from securitykit.core.algorithm import Algorithm
from securitykit.core.policy_registry import get_policy_class
from securitykit.exceptions import ConfigValidationError

logger = logging.getLogger(__name__)


class SecurityFactory:
    """
    Builds Algorithm + Policy from config (dict-like).
    - HASH_VARIANT=<variant>
    - Policy parameters expected as <VARIANT>_<PARAM>.
    """

    def __init__(self, config: dict):
        self.config = config

    def get_policy(self, name: str):
        policy_cls = get_policy_class(name)
        params = inspect.signature(policy_cls).parameters

        values: dict[str, object] = {}
        for p_name, p in params.items():
            env_key = f"{name.upper()}_{p_name.upper()}"
            if env_key in self.config:
                values[p_name] = self.config[env_key]
            elif p.default is inspect._empty:  # required
                raise ConfigValidationError(
                    f"Missing required config key '{env_key}' for policy '{name}'"
                )
            else:  # optional
                logger.warning(
                    "Optional config '%s' missing for policy '%s', using default=%r",
                    env_key, name, p.default,
                )

        return policy_cls(**values)

    def get_algorithm(self) -> Algorithm:
        variant = self.config.get("HASH_VARIANT", "argon2")
        policy = self.get_policy(variant)
        return Algorithm(variant=variant, policy=policy)

