"""
Public wrapper preserving the original API surface:

    loader = ConfigLoader(config_map)
    policy = loader.build(Argon2Policy, prefix="ARGON2_", name="argon2 policy")

Retains:
    - from_env()
    - build()
"""
from __future__ import annotations
import os
from typing import Any, Mapping, Type

from .sources import ValueSource
from .converters import ConverterRegistry
from .builder import PolicyBuilder


class ConfigLoader:
    """
    High-level facade used by the rest of the codebase.
    """

    def __init__(self, config: Mapping[str, Any], converters: ConverterRegistry | None = None):
        self.source = ValueSource(config)
        self.converters = converters or ConverterRegistry()
        self._builder = PolicyBuilder(self.source, self.converters)

    @classmethod
    def from_env(cls) -> "ConfigLoader":
        return cls(os.environ)

    def build(self, policy_cls: Type, prefix: str, name: str):
        """
        Build a policy-like object by inspecting its constructor and mapping
        configuration values with the given prefix.
        """
        return self._builder.build(policy_cls, prefix, name)
