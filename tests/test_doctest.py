# tests/test_doctests.py
"""
Run doctests across the SecurityKit project.

This ensures that all usage examples in module/class/function
docstrings remain correct and in sync with the implementation.
"""

import doctest
import importlib
import pkgutil
import pathlib
import pytest


# Base package
PACKAGE = "securitykit"


def iter_modules(package: str):
    """Yield all modules in the given package recursively."""
    pkg = importlib.import_module(package)
    pkg_path = pathlib.Path(pkg.__file__).parent
    for module in pkgutil.walk_packages([str(pkg_path)], prefix=f"{package}."):
        yield module.name


@pytest.mark.parametrize("modname", list(iter_modules(PACKAGE)))
def test_doctests(modname):
    """Run doctest on a single module."""
    module = importlib.import_module(modname)
    failure_count, _ = doctest.testmod(module, optionflags=doctest.ELLIPSIS)
    assert failure_count == 0, f"Doctest failed in {modname}"
