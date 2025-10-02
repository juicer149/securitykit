"""
Schema export helper for documentation or tooling.
"""
from __future__ import annotations
import inspect
from typing import Any, Type, List, Dict, get_type_hints


def export_schema(policy_cls: Type, prefix: str) -> List[Dict[str, Any]]:
    """
    Returns a list of dictionaries describing the policy class parameters.
    Each entry:
        param        parameter name
        config_key   derived config key (prefix + uppercased param)
        required     bool: no default provided
        default      default value or None if required
        type         textual type (from hints if available)
    """
    sig = inspect.signature(policy_cls).parameters
    hints = get_type_hints(policy_cls)
    rows: list[dict[str, Any]] = []
    for pname, param in sig.items():
        key = f"{prefix}{pname.upper()}"
        required = param.default is inspect._empty
        default = None if required else param.default
        hinted = hints.get(pname, Any)
        if hasattr(hinted, "__name__"):
            type_name = hinted.__name__
        else:
            type_name = str(hinted)
        rows.append(
            {
                "param": pname,
                "config_key": key,
                "required": required,
                "default": default,
                "type": type_name,
            }
        )
    return rows
