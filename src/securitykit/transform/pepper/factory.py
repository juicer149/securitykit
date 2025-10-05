from __future__ import annotations

"""
securitykit.transform.pepper.factory
------------------------------------

PepperFactory builds a PepperApplication — an object that defines
how pepper is applied for a given hashing variant:

- If PEPPER_MODE=hmac and the variant supports a native secret
  (diagnostics.extra['supports_secret'] is True), pass the key as
  algo_kwargs={'secret': <bytes>} and do NOT prehash.
- If PEPPER_MODE=hmac and the variant does NOT support a native secret,
  apply an HMAC prehash pipeline.
- For other modes (noop/prefix/suffix/prefix_suffix/interleave), build
  a prehash pipeline via the standard strategy builder.

Design choice (late binding):
- We import the registry module (not the symbol) to avoid hard-bound references,
  so tests can cleanly monkeypatch securitykit.hashing.registry.get_diagnostic.
"""

from dataclasses import dataclass
from typing import Any, Callable, Dict, Mapping, Optional

from securitykit.utils.config_loader import ConfigLoader
from securitykit.logging_config import logger
from securitykit.exceptions import HashingError

from securitykit.transform.pepper.model import PepperConfig
from securitykit.transform.pepper.builder import build_pepper_strategy
from securitykit.transform.pepper.strategies import HmacStrategy
from securitykit.transform.pepper.pepper_policy import PepperPolicy

# Late-bound registry import for easier testing/monkeypatching
import securitykit.hashing.registry as _reg


@dataclass(frozen=True)
class PepperApplication:
    """
    Defines how the hashing algorithm should apply pepper.

    Attributes:
        prehash_pipeline: Optional function applied to the password before hashing
                          (e.g., HMAC, prefix/suffix, interleave). None means no prehash.
        algo_kwargs:      Extra kwargs passed to the algorithm constructor
                          (e.g., {'secret': b'...'} for native keyed modes).
    """
    prehash_pipeline: Optional[Callable[[str], str]]
    algo_kwargs: Dict[str, Any]


class PepperFactory:
    """
    Construct a PepperApplication using PEPPER_* configuration and variant diagnostics.
    """

    @staticmethod
    def _build_policy(config: Mapping[str, Any]) -> PepperPolicy:
        """
        Parse and validate PEPPER_* configuration.
        """
        loader = ConfigLoader(config)
        return loader.build(PepperPolicy, prefix="PEPPER_", name="PepperPolicy")

    @staticmethod
    def from_config(variant: str, config: Optional[Mapping[str, Any]]) -> PepperApplication:
        """
        Create a PepperApplication for the provided hashing variant and configuration.

        Rules:
        - If pepper is disabled: return no prehash and no algo kwargs.
        - If mode == 'hmac':
            • If diagnostics.extra['supports_secret'] is True:
                - Use native secret (algo_kwargs={'secret': <key-bytes>})
                - Do NOT apply HMAC prehash
            • Else:
                - Apply external HMAC prehash pipeline
        - For other modes (noop/prefix/suffix/prefix_suffix/interleave):
            • Build and return a prehash pipeline via the standard strategy builder.
        """
        if not config:
            return PepperApplication(prehash_pipeline=None, algo_kwargs={})

        policy = PepperFactory._build_policy(config)

        # If pepper is not active, no-op
        if not policy.is_active():
            logger.debug("Pepper disabled — returning no-op PepperApplication.")
            return PepperApplication(prehash_pipeline=None, algo_kwargs={})

        mode = (policy.mode or "noop").lower()

        # HMAC mode: prefer native keyed mode when the variant supports a secret
        if mode == "hmac":
            if not policy.hmac_key:
                raise ValueError("PEPPER_HMAC_KEY must be set when PEPPER_MODE=hmac")

            diag = _reg.get_diagnostic(variant) if variant else None
            extra = getattr(diag, "extra", {}) or {}
            supports_secret = bool(extra.get("supports_secret", False))
            version = getattr(diag, "version", "unknown") if diag else "unknown"

            if supports_secret:
                logger.debug(
                    "PepperFactory: variant '%s' supports native secret (version %s). "
                    "Using algo_kwargs.secret (no prehash).",
                    variant, version,
                )
                return PepperApplication(
                    prehash_pipeline=None,
                    algo_kwargs={"secret": policy.hmac_key.encode("utf-8")},
                )

            # Fallback: external HMAC prehash
            logger.debug(
                "PepperFactory: variant '%s' lacks native secret (version %s). "
                "Using external HMAC prehash pipeline.",
                variant, version,
            )
            strategy = HmacStrategy(
                key=policy.hmac_key.encode("utf-8"),
                algo=(policy.hmac_algo or "sha256"),
            )

            def prehash(pw: str) -> str:
                return strategy.apply(pw)

            return PepperApplication(prehash_pipeline=prehash, algo_kwargs={})

        # Other modes (noop/prefix/suffix/prefix_suffix/interleave) → build pipeline
        cfg = PepperConfig(
            enabled=policy.enabled,
            mode=policy.mode,
            secret=policy.secret,
            prefix=policy.prefix,
            suffix=policy.suffix,
            interleave_freq=policy.interleave_freq,
            interleave_token=policy.interleave_token,
            hmac_key=policy.hmac_key,
            hmac_algo=policy.hmac_algo,
        )

        try:
            strategy = build_pepper_strategy(cfg)
        except Exception as e:
            raise HashingError(f"Failed to construct pepper strategy: {e}") from e

        def prehash(pw: str) -> str:
            return strategy.apply(pw)

        logger.debug("PepperFactory: using '%s' prehash pipeline for variant=%s.", mode, variant)
        return PepperApplication(prehash_pipeline=prehash, algo_kwargs={})
