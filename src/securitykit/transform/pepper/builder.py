"""
securitykit.transform.pepper.builder
------------------------------------

Responsible for translating a normalized PepperConfig into a concrete
PepperStrategy instance.

Design goals:
    • Keep the ConfigLoader generic — all semantic validation happens here.
    • Make strategy selection explicit and deterministic.
    • Fail fast on invalid configuration, but never crash the system
      (fallback handled by the pipeline layer).

Also provides build_from_config(), a convenience helper for adapter.py
to construct a strategy directly from an environment mapping.
"""

from __future__ import annotations

import hashlib
from typing import Any, Mapping

from securitykit.logging_config import logger
from securitykit.exceptions import (
    PepperConfigError,
    UnknownPepperStrategyError,
    PepperStrategyConstructionError,
)
from securitykit.utils.config_loader import ConfigLoader
from .core import get_strategy_factory
from .model import PepperConfig
from . import strategies  # noqa: F401  (ensures built-ins are registered)


# Modes that only decorate the password. They are kept for compatibility
# with existing hashes, but they do not add cryptographic strength.
_DECORATION_MODES = frozenset(
    {"prefix", "suffix", "prefix_suffix", "interleave"}
)


# ---------------------------------------------------------------------------
# Core builder
# ---------------------------------------------------------------------------

def build_pepper_strategy(cfg: PepperConfig):
    """
    Build a concrete PepperStrategy instance from a PepperConfig object.

    Handles all semantic validation and parameter mapping.
    """
    mode = (cfg.mode or "noop").lower()

    # --- Disabled or NoOp mode ------------------------------------------
    if not cfg.enabled or mode == "noop":
        return get_strategy_factory("noop")()

    secret = cfg.secret or ""

    if mode in _DECORATION_MODES:
        logger.warning(
            "PEPPER_MODE=%s only decorates the password and is not "
            "cryptographic. Prefer PEPPER_MODE=hmac.",
            mode,
        )

    # --- Prefix ---------------------------------------------------------
    if mode == "prefix":
        return get_strategy_factory("prefix")(prefix=cfg.prefix or secret)

    # --- Suffix ---------------------------------------------------------
    if mode == "suffix":
        return get_strategy_factory("suffix")(suffix=cfg.suffix or secret)

    # --- Prefix + Suffix ------------------------------------------------
    if mode == "prefix_suffix":
        return get_strategy_factory("prefix_suffix")(
            prefix=cfg.prefix or secret,
            suffix=cfg.suffix or secret,
        )

    # --- Interleave -----------------------------------------------------
    if mode == "interleave":
        if cfg.interleave_freq <= 0:
            raise PepperConfigError(
                "PEPPER_INTERLEAVE_FREQ must be > 0 for interleave mode"
            )
        token = cfg.interleave_token or secret
        return get_strategy_factory("interleave")(
            token=token,
            frequency=cfg.interleave_freq,
        )

    # --- HMAC -----------------------------------------------------------
    if mode == "hmac":
        if not cfg.hmac_key:
            raise PepperConfigError("PEPPER_HMAC_KEY required for hmac mode")

        if len(cfg.hmac_key) < 8:
            logger.warning(
                "PEPPER_HMAC_KEY is very short (<8 chars) – consider a stronger key."
            )

        algo_name = cfg.hmac_algo or "sha256"

        # Validate that algorithm exists in hashlib
        try:
            getattr(hashlib, algo_name)
        except AttributeError as e:
            raise PepperStrategyConstructionError(
                f"Unsupported HMAC algorithm '{algo_name}'"
            ) from e

        # Construct the strategy safely
        try:
            return get_strategy_factory("hmac")(
                key=cfg.hmac_key.encode("utf-8"),
                algo=algo_name,
            )
        except PepperStrategyConstructionError:
            raise
        except Exception as e:
            raise PepperStrategyConstructionError(
                f"Failed to construct hmac strategy: {e}"
            ) from e

    # --- Unknown mode ---------------------------------------------------
    raise UnknownPepperStrategyError(f"Unknown PEPPER_MODE '{cfg.mode}'")


# ---------------------------------------------------------------------------
# Adapter integration helper
# ---------------------------------------------------------------------------

def build_from_config(mapping: Mapping[str, Any]):
    """
    High-level helper used by PepperAdapter.

    Parses a raw configuration mapping (e.g. os.environ or a dict of
    PEPPER_* keys) using ConfigLoader, builds a PepperConfig, and then
    instantiates the correct PepperStrategy.

    Example:
        >>> import os
        >>> os.environ['PEPPER_MODE'] = 'prefix'
        >>> os.environ['PEPPER_PREFIX'] = '^'
        >>> strategy = build_from_config(os.environ)
        >>> strategy.apply("pass")
        '^pass'
    """
    loader = ConfigLoader(mapping)
    cfg = loader.build(PepperConfig, prefix="PEPPER_", name="pepper config")
    return build_pepper_strategy(cfg)
