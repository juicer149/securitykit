"""
Hashing subpackage.

Provides registries and load_all() helper for algorithm/policy discovery.
Discovery is NOT automatically triggered here to keep imports cheap.
Call load_all() explicitly or rely on lazy loading in the factory.
"""
from .registry import load_all
from . import algorithm_registry, policy_registry

__all__ = [
    "load_all",
    "algorithm_registry",
    "policy_registry",
]
