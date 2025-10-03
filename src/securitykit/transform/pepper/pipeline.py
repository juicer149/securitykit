"""
Pepper application pipeline:

1. Parse & cache PepperConfig (via ConfigLoader)
2. Build (and cache) strategy
3. Apply strategy

Any PepperError results in a logged message and fallback to NoOp.
"""
from __future__ import annotations
from functools import lru_cache
from typing import Mapping, Any

from securitykit.utils.config_loader import ConfigLoader
from securitykit.logging_config import logger
from securitykit.exceptions import PepperError
from .model import PepperConfig
from .builder import build_pepper_strategy
from .core import PepperStrategy, get_strategy_factory

PEPPER_PREFIX = "PEPPER_"


def _build_config(mapping: Mapping[str, Any]) -> PepperConfig:
    loader = ConfigLoader(mapping)
    return loader.build(PepperConfig, prefix=PEPPER_PREFIX, name="pepper config")


def _snapshot(mapping: Mapping[str, Any]) -> tuple[tuple[str, str], ...]:
    items: list[tuple[str, str]] = []
    for k, v in mapping.items():
        if k.startswith(PEPPER_PREFIX):
            items.append((k, str(v)))
    return tuple(sorted(items))


@lru_cache(maxsize=1)
def _cached_strategy(snapshot: tuple[tuple[str, str], ...]) -> PepperStrategy:
    mapping = {k: v for k, v in snapshot}
    try:
        cfg = _build_config(mapping)
        return build_pepper_strategy(cfg)
    except PepperError as e:
        logger.error("Pepper strategy failure (%s) → noop fallback", e)
        return get_strategy_factory("noop")()
    except Exception as e:  # pragma: no cover (unexpected)
        logger.exception("Unexpected pepper construction error: %s", e)
        return get_strategy_factory("noop")()


def apply_pepper(
    password: str,
    config: Mapping[str, Any],
) -> str:
    """
    Apply configured pepper strategy.

    Returns the transformed password (never raises on pepper issues;
    logs and falls back to noop strategy instead).
    """
    if not password:
        return password

    snap = _snapshot(config)
    strategy = _cached_strategy(snap)
    return strategy.apply(password)
