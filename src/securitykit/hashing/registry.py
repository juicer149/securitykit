"""
Auto-discovery for hashing policies & algorithms.

- Imports immediate submodules under securitykit.hashing.policies and
  securitykit.hashing.algorithms exactly once (decorators register classes).
- Supports an optional force reload (restores original snapshots via
  the specialized registries' restore functions).
- Caches a diagnostics snapshot after initial load for all supported variants.
"""
from __future__ import annotations
import importlib
import pkgutil
from typing import Iterable, Dict

from securitykit.logging_config import logger
from securitykit.hashing.capabilities import CapabilityInfo
from securitykit.hashing.diagnostics import collect_all_diagnostics

_DISCOVERED = False
_DIAGNOSTIC_SNAPSHOT: Dict[str, CapabilityInfo] = {}


def _iter_children(pkg) -> Iterable[str]:
    for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
        yield f"{pkg.__name__}.{mod_name}"


def _import_all(package_module_name: str) -> None:
    try:
        pkg = importlib.import_module(package_module_name)
    except Exception as e:
        logger.error("Failed to import package %s: %s", package_module_name, e)
        return
    for full in _iter_children(pkg):
        try:
            importlib.import_module(full)
        except Exception as e:
            logger.error("Failed to import submodule %s: %s", full, e)


def load_all(force: bool = False) -> None:
    global _DISCOVERED, _DIAGNOSTIC_SNAPSHOT

    if _DISCOVERED and not force:
        return

    from securitykit.hashing import algorithm_registry, policy_registry

    if force:
        algorithm_registry.restore_from_snapshots()
        policy_registry.restore_from_snapshots()
        logger.debug("Registries restored (force=True).")

    _import_all("securitykit.hashing.policies")
    _import_all("securitykit.hashing.algorithms")

    # Build diagnostics snapshot once
    _DIAGNOSTIC_SNAPSHOT = collect_all_diagnostics()
    logger.debug(
        "Diagnostics snapshot built: %s",
        {k: v.to_dict() for k, v in _DIAGNOSTIC_SNAPSHOT.items()},
    )

    _DISCOVERED = True
    logger.debug("Hashing discovery complete (force=%s).", force)


def get_diagnostic(variant: str) -> CapabilityInfo | None:
    """Return cached diagnostic info for a specific algorithm variant."""
    return _DIAGNOSTIC_SNAPSHOT.get(variant.lower())
