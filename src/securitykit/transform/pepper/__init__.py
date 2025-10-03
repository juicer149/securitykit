"""
Public pepper API.

Typical usage from an algorithm:

    from securitykit.transform.pepper import apply_pepper
    transformed = apply_pepper(raw_password, os.environ)
"""
from .pipeline import apply_pepper
from .core import list_strategies

__all__ = ["apply_pepper", "list_strategies"]
