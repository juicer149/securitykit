"""
Built‑in pepper strategies.

All strategies are intentionally simple; strong cryptographic
augmentation should be explicit (HMAC).
"""
from __future__ import annotations
import hmac
import hashlib
from dataclasses import dataclass
from typing import ClassVar

from securitykit.exceptions import PepperStrategyConstructionError
from .core import register_strategy, PepperStrategy


@register_strategy("noop")
@dataclass(frozen=True)
class NoOpStrategy:
    """Does nothing (default safe fallback)."""
    name: ClassVar[str] = "noop"

    def apply(self, password: str) -> str:  # pragma: no cover (trivial)
        return password


@register_strategy("prefix")
@dataclass(frozen=True)
class PrefixStrategy:
    """Prepends a constant prefix."""
    name: ClassVar[str] = "prefix"
    prefix: str

    def apply(self, password: str) -> str:
        return f"{self.prefix}{password}"


@register_strategy("suffix")
@dataclass(frozen=True)
class SuffixStrategy:
    """Appends a constant suffix."""
    name: ClassVar[str] = "suffix"
    suffix: str

    def apply(self, password: str) -> str:
        return f"{password}{self.suffix}"


@register_strategy("prefix_suffix")
@dataclass(frozen=True)
class PrefixSuffixStrategy:
    """Wraps a password in prefix + suffix."""
    name: ClassVar[str] = "prefix_suffix"
    prefix: str
    suffix: str

    def apply(self, password: str) -> str:
        return f"{self.prefix}{password}{self.suffix}"


@register_strategy("interleave")
@dataclass(frozen=True)
class InterleaveStrategy:
    """
    Inserts a token every N characters (obfuscation, NOT cryptographic).
    """
    name: ClassVar[str] = "interleave"
    token: str
    frequency: int

    def apply(self, password: str) -> str:
        if not self.token or self.frequency <= 0:
            return password
        out = []
        ti = 0
        for i, ch in enumerate(password):
            out.append(ch)
            if (i + 1) % self.frequency == 0:
                out.append(self.token[ti % len(self.token)])
                ti += 1
        return "".join(out)


@register_strategy("hmac")
@dataclass(frozen=True)
class HmacStrategy:
    """
    Cryptographic strategy: HMAC(key, password) → hex digest.
    """
    name: ClassVar[str] = "hmac"
    key: bytes
    algo: str = "sha256"

    def apply(self, password: str) -> str:
        try:
            func = getattr(hashlib, self.algo)
        except AttributeError as e:
            raise PepperStrategyConstructionError(
                f"Unsupported HMAC algorithm '{self.algo}'"
            ) from e
        try:
            return hmac.new(self.key, password.encode("utf-8"), func).hexdigest()
        except Exception as e:  # pragma: no cover (defensive)
            raise PepperStrategyConstructionError(
                f"Failed HMAC operation: {e}"
            ) from e
