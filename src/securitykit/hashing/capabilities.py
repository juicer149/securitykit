from __future__ import annotations
from dataclasses import dataclass, asdict
from typing import Any

@dataclass(frozen=True)
class CapabilityInfo:
    """
    Unified diagnostics structure for all hashing algorithms.
    """
    available: bool
    version: str
    extra: dict[str, Any] | None = None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

