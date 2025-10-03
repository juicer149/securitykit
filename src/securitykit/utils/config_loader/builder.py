"""
PolicyBuilder: coordinates:
  - signature introspection
  - raw value lookup
  - conversion
  - final instantiation
  - basic post-conversion type enforcement (int/float/bool) to surface errors early
"""
from __future__ import annotations
import inspect
from typing import Any, Type, Dict, get_type_hints

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
        Collect resolved constructor parameter values.
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

        # Early exit if collection issues
        if errors:
            raise ConfigValidationError(
                f"Errors building {label}: " + "; ".join(errors)
            )

        # Type enforcement (basic) — only primitive scalar checks
        hints = get_type_hints(policy_cls)
        type_errors: list[str] = []
        for field, expected in hints.items():
            if field not in resolved:
                continue
            val = resolved[field]
            # Only enforce for simple primitives
            if expected in (int, float, bool):
                if isinstance(val, expected):
                    continue
                # Attempt coercion
                try:
                    if expected is bool:
                        # Strict: only accept actual bool; do not coerce arbitrary strings/numbers
                        raise TypeError("Expected boolean literal")
                    coerced = expected(val)  # type: ignore
                    resolved[field] = coerced
                except Exception:
                    type_errors.append(
                        f"Type mismatch for '{prefix}{field.upper()}': expected {expected.__name__}, got {type(val).__name__}"
                    )
        if type_errors:
            raise ConfigValidationError(
                f"Errors building {label}: " + "; ".join(type_errors)
            )

        return resolved

    def build(self, policy_cls: Type, prefix: str, label: str):
        """
        Instantiate the policy class with resolved + validated arguments.
        """
        values = self._collect(policy_cls, prefix, label)
        try:
            return policy_cls(**values)
        except Exception as e:
            raise ConfigValidationError(
                f"Invalid configuration for {label}: {e}"
            ) from e
