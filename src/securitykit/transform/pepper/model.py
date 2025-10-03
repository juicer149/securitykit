"""
Dataclass representing normalized pepper configuration as parsed by
ConfigLoader. All string fields default to empty; logic/validation
happens in the builder layer.
"""
from __future__ import annotations
from dataclasses import dataclass


@dataclass(frozen=True)
class PepperConfig:
    enabled: bool = True
    mode: str = "noop"

    # Generic secret (used if explicit prefix/suffix are not provided)
    secret: str = ""

    prefix: str = ""
    suffix: str = ""

    interleave_freq: int = 0
    interleave_token: str = ""

    hmac_key: str = ""
    hmac_algo: str = "sha256"
