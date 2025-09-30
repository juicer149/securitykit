# securitykit/core/interfaces.py
from typing import Protocol, runtime_checkable, Any, ClassVar



@runtime_checkable
class AlgorithmProtocol(Protocol):
    """
    All algorithm implementations must follow this interface.
    """

    def __init__(self, policy: object | None = None, pepper: str | None = None) -> None: ...
    def hash(self, password: str) -> str: ...
    def verify(self, stored_hash: str, password: str) -> bool: ...
    def needs_rehash(self, stored_hash: str) -> bool: ...


@runtime_checkable
class PolicyProtocol(Protocol):
    """
    All policy classes should follow this interface.
    Typically implemented as a dataclass.
    """

    BENCH_SCHEMA: ClassVar[dict[str, list[int]]] 

    def to_dict(self) -> dict[str, Any]: ...
