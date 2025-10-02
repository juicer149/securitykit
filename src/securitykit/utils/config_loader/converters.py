"""
Conversion pipeline for raw configuration values.

ConverterRegistry executes a chain of converter functions in order.
You can register custom converters to apply before or after the defaults.

Important: Numeric strings like "1" or "0" are NOT treated as booleans.
Boolean recognition is limited to: true/on/yes and false/off/no.
"""
from __future__ import annotations
from typing import Any, Callable, List
import re

# Boolean tokens (int-like "1"/"0" deliberately excluded to avoid misinterpreting numeric params)
_BOOL_TRUE = {"true", "on", "yes"}
_BOOL_FALSE = {"false", "off", "no"}

_SIZE_SUFFIXES = {
    "k": 1024,
    "kb": 1024,
    "m": 1024 * 1024,
    "mb": 1024 * 1024,
    "g": 1024 * 1024 * 1024,
    "gb": 1024 * 1024 * 1024,
}


def _try_size(value: str):
    """
    Try to parse size-like strings: 64k, 32M, 1G, 1024, etc.
    Returns an int or None if not size-like.
    """
    m = re.fullmatch(r"\s*([0-9]+)([kKmMgGbB]{0,2})\s*", value)
    if not m:
        return None
    number = int(m.group(1))
    suffix = m.group(2).lower()
    if suffix in _SIZE_SUFFIXES:
        return number * _SIZE_SUFFIXES[suffix]
    if suffix in ("", "b"):
        return number
    return None


def default_parse(value: Any) -> Any:
    """
    Default heuristic parsing:
      - Already non-string → return as-is
      - Booleans: true/on/yes, false/off/no
      - Sizes: "8k", "64M", "1G"
      - Integers
      - Floats
      - Lists separated by comma or semicolon
      - Otherwise original string
    """
    if not isinstance(value, str):
        return value

    raw = value.strip()
    low = raw.lower()

    if low in _BOOL_TRUE:
        return True
    if low in _BOOL_FALSE:
        return False

    sized = _try_size(raw)
    if sized is not None:
        return sized

    if re.fullmatch(r"-?[0-9]+", raw):
        try:
            return int(raw)
        except ValueError:
            pass

    if re.fullmatch(r"-?[0-9]+\.[0-9]+", raw):
        try:
            return float(raw)
        except ValueError:
            pass

    if "," in raw or ";" in raw:
        parts = re.split(r"[;,]", raw)
        return [p.strip() for p in parts if p.strip()]

    return value


class ConverterRegistry:
    """
    Maintains an ordered list of converters. Each converter is a callable
    value -> value. They are applied sequentially.
    """

    def __init__(self):
        self._chain: List[Callable[[Any], Any]] = [default_parse]

    def register_front(self, fn: Callable[[Any], Any]) -> None:
        """
        Register a converter with highest priority (runs first).
        """
        self._chain.insert(0, fn)

    def register_back(self, fn: Callable[[Any], Any]) -> None:
        """
        Register a converter with lowest priority (runs last).
        """
        self._chain.append(fn)

    def convert(self, raw: Any) -> Any:
        out = raw
        for fn in self._chain:
            out = fn(out)
        return out
