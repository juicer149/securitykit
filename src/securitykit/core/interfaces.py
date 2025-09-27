# securitykit/core/interfaces.py
from typing import Protocol, runtime_checkable


@runtime_checkable
class AlgorithmProtocol(Protocol):
    """
    Alla algoritm-implementationer måste följa detta interface.
    """

    def __init__(self, policy: object | None = None) -> None: ...

    def hash(self, password: str) -> str: ...

    def verify(self, stored_hash: str, password: str) -> bool: ...

