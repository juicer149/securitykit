"""
PolicyBuilder: coordinates:
  - signature introspection
  - raw value lookup
  - conversion
  - final instantiation
"""
from __future__ import annotations
import inspect
from typing import Any, Type, Dict

from securitykit.logging_config import logger
from securitykit.exceptions import ConfigValidationError

from .sources import ValueSource
from .converters import ConverterRegistry


class PolicyBuilder:
    """
    Builds a policy-like class by inspecting its __init__ signature
    (dataclass or plain class) and resolving parameters from a ValueSource.
    """

    def __init__(self, source: ValueSource, converters: ConverterRegistry):
        self.source = source
        self.converters = converters

    def _collect(self, policy_cls: Type, prefix: str, label: str) -> Dict[str, Any]:
        """
        Collects final parameter values:
          - Required parameters must exist → error if missing
          - Optional parameters fallback to their default and log a warning
        """
        params = inspect.signature(policy_cls).parameters
        resolved: dict[str, Any] = {}
        errors: list[str] = []

        for pname, param in params.items():
            key = f"{prefix}{pname.upper()}"
            if self.source.has(key):
                raw = self.source.get(key)
                try:
                    resolved[pname] = self.converters.convert(raw)
                except Exception as e:
                    errors.append(f"Invalid value for '{key}': {e}")
            else:
                if param.default is inspect._empty:
                    errors.append(f"Missing required '{key}'")
                else:
                    resolved[pname] = param.default
                    logger.warning(
                        "Optional config '%s' missing for %s, using default=%r",
                        key,
                        label,
                        param.default,
                    )
        if errors:
            raise ConfigValidationError(
                f"Errors building {label}: " + "; ".join(errors)
            )
        return resolved

    def build(self, policy_cls: Type, prefix: str, label: str):
        """
        Returns an instantiated policy instance.
        """
        values = self._collect(policy_cls, prefix, label)
        try:
            return policy_cls(**values)
        except Exception as e:
            raise ConfigValidationError(
                f"Invalid configuration for {label}: {e}"
            ) from e
