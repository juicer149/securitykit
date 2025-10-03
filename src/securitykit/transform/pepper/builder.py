"""
Build a concrete pepper strategy from a PepperConfig instance.

All validation that requires semantic checks (e.g. missing HMAC key,
invalid frequency) lives here so the parsing layer (ConfigLoader) stays generic.
"""
from __future__ import annotations
import hashlib

from securitykit.logging_config import logger
from securitykit.exceptions import (
    PepperConfigError,
    UnknownPepperStrategyError,
    PepperStrategyConstructionError,
)
from .core import get_strategy_factory
from .model import PepperConfig
from . import strategies  # noqa: F401 (register built-ins)


def build_pepper_strategy(cfg: PepperConfig):
    """
    Translate PepperConfig into a concrete PepperStrategy instance.
    Raise Pepper* exceptions for invalid config.
    """
    mode = (cfg.mode or "noop").lower()

    if not cfg.enabled or mode == "noop":
        return get_strategy_factory("noop")()

    secret = cfg.secret or ""

    if mode == "prefix":
        return get_strategy_factory("prefix")(prefix=cfg.prefix or secret)

    if mode == "suffix":
        return get_strategy_factory("suffix")(suffix=cfg.suffix or secret)

    if mode == "prefix_suffix":
        return get_strategy_factory("prefix_suffix")(
            prefix=cfg.prefix or secret, suffix=cfg.suffix or secret
        )

    if mode == "interleave":
        if cfg.interleave_freq <= 0:
            logger.warning("PEPPER_INTERLEAVE_FREQ <= 0 → falling back to noop")
            return get_strategy_factory("noop")()
        token = cfg.interleave_token or secret
        return get_strategy_factory("interleave")(
            token=token, frequency=cfg.interleave_freq
        )

    if mode == "hmac":
        if not cfg.hmac_key:
            raise PepperConfigError("PEPPER_HMAC_KEY required for hmac mode")
        if len(cfg.hmac_key) < 8:
            logger.warning(
                "PEPPER_HMAC_KEY is very short (<8 chars) – consider a stronger key."
            )
        # Early algorithm validation so tests expecting build-time failure pass
        try:
            getattr(hashlib, cfg.hmac_algo or "sha256")
        except AttributeError as e:
            raise PepperStrategyConstructionError(
                f"Unsupported HMAC algorithm '{cfg.hmac_algo}'"
            ) from e
        try:
            return get_strategy_factory("hmac")(
                key=cfg.hmac_key.encode("utf-8"), algo=cfg.hmac_algo or "sha256"
            )
        except PepperStrategyConstructionError:
            raise
        except Exception as e:
            raise PepperStrategyConstructionError(
                f"Failed to construct hmac strategy: {e}"
            ) from e

    raise UnknownPepperStrategyError(f"Unknown PEPPER_MODE '{cfg.mode}'")
