"""
Config loading & policy construction toolkit.

Public API:
    - ConfigLoader            High-level entry point (preserves original interface)
    - ConverterRegistry       Register custom conversion functions
    - ValueSource             Abstraction for config value access
    - export_schema           Utility to describe expected configuration

All docstrings and comments intentionally minimal & explicit.
"""
from .loader import ConfigLoader
from .converters import ConverterRegistry, default_parse
from .sources import ValueSource
from .schema import export_schema

__all__ = [
    "ConfigLoader",
    "ConverterRegistry",
    "ValueSource",
    "default_parse",
    "export_schema",
]
