"""
Internal lightweight protocols used inside algorithm implementations
to get strong typing for policy attribute access without bloating the
public PolicyProtocol (which stays minimal for registry / bench use).

They are deliberately NOT registered anywhere; pure structural typing.
"""

from __future__ import annotations
from typing import Protocol


class Argon2PolicyLike(Protocol):
    time_cost: int
    memory_cost: int
    parallelism: int
    hash_length: int
    salt_length: int
    def to_dict(self) -> dict[str, object]: ...


class BcryptPolicyLike(Protocol):
    rounds: int
    def to_dict(self) -> dict[str, object]: ...
