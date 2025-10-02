"""
Value source abstractions.

Currently only a simple mapping wrapper.
Can be extended later (e.g. layered sources or remote lookups).
"""
from typing import Mapping, Any


class ValueSource:
    """
    Wraps a generic mapping (such as os.environ or a dict) and provides
    simple access helpers.
    """

    def __init__(self, mapping: Mapping[str, Any]):
        self._mapping = mapping

    def has(self, key: str) -> bool:
        return key in self._mapping

    def get(self, key: str) -> Any:
        return self._mapping.get(key)

    def keys(self):
        return self._mapping.keys()
