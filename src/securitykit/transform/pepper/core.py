"""
Pepper strategy registry & protocol (lazy registration safe).
"""
from __future__ import annotations
from typing import Protocol, ClassVar, Callable, Dict

from securitykit.exceptions import (
    PepperStrategyRegistrationError,
    UnknownPepperStrategyError,
)


class PepperStrategy(Protocol):
    name: ClassVar[str]
    def apply(self, password: str) -> str: ...


# Internal strategy registry
_STRATEGIES: Dict[str, Callable[..., PepperStrategy]] = {}


def register_strategy(name: str):
    """
    Decorator to register a strategy factory under a case-insensitive key.

    Idempotent for the *same* callable; raises if a different object
    attempts to reuse the name.
    """
    def decorator(factory: Callable[..., PepperStrategy]):
        key = name.lower()
        existing = _STRATEGIES.get(key)
        if existing is not None and existing is not factory:
            raise PepperStrategyRegistrationError(
                f"Pepper strategy '{name}' already registered."
            )
        _STRATEGIES[key] = factory
        return factory
    return decorator


def _lazy_import_strategies() -> None:
    """
    Import default strategies on first lookup to avoid ordering issues
    (e.g. when pipeline is imported before strategies).
    """
    if _STRATEGIES:
        return
    try:
        from . import strategies  # noqa: F401
    except Exception:
        # Silently ignore – actual lookup will raise UnknownPepperStrategyError
        pass


def get_strategy_factory(name: str) -> Callable[..., PepperStrategy]:
    _lazy_import_strategies()
    try:
        return _STRATEGIES[name.lower()]
    except KeyError as e:
        raise UnknownPepperStrategyError(
            f"Unknown pepper strategy '{name}'. Available={list(_STRATEGIES)}"
        ) from e


def list_strategies() -> list[str]:
    _lazy_import_strategies()
    return list(_STRATEGIES.keys())
