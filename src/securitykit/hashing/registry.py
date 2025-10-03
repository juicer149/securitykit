"""
Auto-discovery for hashing policies & algorithms.

- Imports immediate submodules under securitykit.hashing.policies and
  securitykit.hashing.algorithms exactly once (decorators register classes).
- Supports an optional force reload (restores original snapshots via
  the specialized registries' restore functions).
"""

from __future__ import annotations
import importlib
import pkgutil
from typing import Iterable

from securitykit.logging_config import logger

_DISCOVERED = False


def _iter_children(pkg) -> Iterable[str]:
    for _, mod_name, _ in pkgutil.iter_modules(pkg.__path__):
        yield f"{pkg.__name__}.{mod_name}"


def _import_all(package_module_name: str) -> None:
    try:
        pkg = importlib.import_module(package_module_name)
    except Exception as e:  # pragma: no cover
        logger.error("Failed to import package %s: %s", package_module_name, e)
        return
    for full in _iter_children(pkg):
        try:
            importlib.import_module(full)
        except Exception as e:  # pragma: no cover
            logger.error("Failed to import submodule %s: %s", full, e)


def load_all(force: bool = False) -> None:
    """
    Perform one-time discovery (or restore snapshots if force=True).

    force=True:
        - Restores original snapshot state in each specialized registry
          (algorithm + policy).
        - Re-imports modules (idempotent decorator writes).
    """
    global _DISCOVERED
    if _DISCOVERED and not force:
        return

    from securitykit.hashing import algorithm_registry, policy_registry

    if force:
        # restore original class objects
        algorithm_registry.restore_from_snapshots()
        policy_registry.restore_from_snapshots()
        logger.debug("Registries restored from snapshots (force=True).")

    # Always (re-)import modules; decorators are idempotent for same class.
    _import_all("securitykit.hashing.policies")
    _import_all("securitykit.hashing.algorithms")

    _DISCOVERED = True
    logger.debug("Hashing discovery complete (force=%s).", force)
