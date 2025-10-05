from __future__ import annotations

"""
Typed, validated pepper configuration built via ConfigLoader.

This policy is intentionally minimal and mirrors your existing PEPPER_* keys.
It is immutable (frozen=True) so callers can safely share instances.
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class PepperPolicy:
    """
    Canonical pepper policy parsed from PEPPER_* keys.

    Fields:
        enabled: Master on/off switch (default True).
        mode: One of: "noop", "prefix", "suffix", "prefix_suffix", "interleave", "hmac".
        secret: Generic secret used by simple modes as fallback (prefix/suffix/interleave).
        prefix/suffix: Explicit decorations for the respective modes.
        interleave_freq: Insert token every N characters (<=0 ⇒ no-op in strategy).
        interleave_token: Token sequence for interleave mode; falls back to `secret` if empty.
        hmac_key: Required for mode="hmac".
        hmac_algo: Hash algorithm for HMAC mode (must exist in hashlib).
    """
    enabled: bool = True
    mode: str = "noop"

    # Simple modes (non-cryptographic decoration)
    secret: str = ""
    prefix: str = ""
    suffix: str = ""
    interleave_freq: int = 0
    interleave_token: str = ""

    # Cryptographic mode
    hmac_key: str = ""
    hmac_algo: str = "sha256"

    # Convenience
    def is_active(self) -> bool:
        return self.enabled and self.mode.lower() != "noop"
