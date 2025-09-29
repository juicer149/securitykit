# securitykit/core/factory.py
import inspect
from typing import Any, Mapping, Type

from securitykit.services.password_security import PasswordSecurity
from securitykit.core.algorithm import Algorithm
from securitykit.core.policy_registry import get_policy_class
from securitykit.policies.password import PasswordPolicy
from securitykit.exceptions import ConfigValidationError
from securitykit.logging_config import logger


# Boolean string mapping (explicit, no int parsing like "0"/"1")
BOOL_MAP = {
    "true": True,
    "on": True,
    "yes": True,
    "false": False,
    "off": False,
    "no": False,
}


def _parse_value(value: str) -> Any:
    """Convert config string to int/bool if applicable, otherwise keep raw value."""
    if isinstance(value, str):
        v = value.strip()
        if v.isdigit() or (v.startswith("-") and v[1:].isdigit()):
            return int(v)
        v_lower = v.lower()
        if v_lower in BOOL_MAP:
            return BOOL_MAP[v_lower]
    return value


def _build_policy(policy_cls: Type, config: Mapping[str, Any], prefix: str, name: str) -> object:
    """Helper to construct a policy from config with validation and defaults."""
    params = inspect.signature(policy_cls).parameters
    values: dict[str, object] = {}

    for p_name, p in params.items():
        env_key = f"{prefix}{p_name.upper()}"
        if env_key in config:
            try:
                values[p_name] = _parse_value(config[env_key])
            except (ValueError, TypeError) as e:
                raise ConfigValidationError(f"Invalid value for '{env_key}': {e}")
        elif p.default is inspect._empty:
            raise ConfigValidationError(f"Missing required config key '{env_key}' for {name}")
        else:
            values[p_name] = p.default
            logger.warning(
                "Optional config '%s' missing for %s, using default=%r",
                env_key,
                name,
                p.default,
            )

    try:
        return policy_cls(**values)
    except (ValueError, TypeError) as e:
        raise ConfigValidationError(f"Invalid configuration for {name}: {e}")


class SecurityFactory:
    """
    Factory for constructing password hashing algorithms and policies from config.
    Supports env/dict configs for flexible setup.
    """

    def __init__(self, config: Mapping[str, Any]):
        self.config = config

    def get_policy(self, name: str) -> object:
        """Hashing policy (e.g. Argon2)."""
        policy_cls = get_policy_class(name)
        return _build_policy(
            policy_cls,
            self.config,
            prefix=f"{name.upper()}_",
            name=f"policy '{name}'",
        )

    def get_algorithm(self) -> Algorithm:
        """
        Return an Algorithm wrapper for the chosen HASH_VARIANT.
        Passes optional global PEPPER_VALUE to the algorithm implementation.
        """
        variant = str(self.config.get("HASH_VARIANT", "argon2")).lower()
        policy = self.get_policy(variant)

        # 🔑 global pepper support (applies to all algorithms)
        pepper = self.config.get("PEPPER_VALUE") or None

        return Algorithm(variant=variant, policy=policy, pepper=pepper)

    def get_password_policy(self) -> PasswordPolicy:
        """Always return a PasswordPolicy (no opt-out flag anymore)."""
        return _build_policy(
            PasswordPolicy,
            self.config,
            prefix="PASSWORD_",
            name="PasswordPolicy",
        )

    def get_password_security(self) -> PasswordSecurity:
        """High-level API = password validation + hashing."""
        policy = self.get_password_policy()
        algo = self.get_algorithm()
        return PasswordSecurity(policy, algo)
