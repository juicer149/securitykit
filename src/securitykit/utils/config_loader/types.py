"""
Type helpers placeholder.

Can be extended for:
  - Optional[X] normalization
  - list[T] decomposition
  - future advanced typing logic
"""
from typing import Any, get_origin, get_args


def normalize_type(t: Any) -> Any:
    """
    Simplify / normalize generic types.
    Currently minimal and returns original or the origin type.
    """
    origin = get_origin(t)
    if origin is None:
        return t
    if origin is list:
        return list
    return origin
