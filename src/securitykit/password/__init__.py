"""
securitykit.password
====================

Password policy, validation, and strength evaluation.

This subpackage provides:
  - Declarative password policies (`PasswordPolicy`)
  - Hard + soft validation (`PasswordValidator`)
  - Strength scoring and UX feedback (`PasswordStrengthEvaluator`)
  - Factory integration for environment configuration (`PasswordFactory`)
"""

from __future__ import annotations
from typing import Any
import importlib

__all__ = [
    "PasswordPolicy",
    "PasswordValidator",
    "PasswordStrengthEvaluator",
    "PasswordFactory",
]

# Mapping for lazy resolution (avoids import-time side effects)
_MAPPING = {
    "PasswordPolicy": "securitykit.password.policy",
    "PasswordValidator": "securitykit.password.validator",
    "PasswordStrengthEvaluator": "securitykit.password.strength_evaluator",
    "PasswordFactory": "securitykit.password.factory",
}


def _import_attr(module_path: str, name: str) -> Any:
    mod = importlib.import_module(module_path)
    return getattr(mod, name)


def __getattr__(name: str) -> Any:
    """
    Lazily resolve imports when accessed.

    Example:
        >>> from securitykit.password import PasswordValidator
        >>> PasswordValidator
        <class 'securitykit.password.validator.PasswordValidator'>
    """
    if name not in __all__:
        raise AttributeError(f"securitykit.password has no attribute '{name}'")

    module_path = _MAPPING[name]
    return _import_attr(module_path, name)


def __dir__() -> list[str]:
    """Ensure IDEs and REPLs show the public API cleanly."""
    return sorted(__all__)
