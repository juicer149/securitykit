from __future__ import annotations
from typing import Protocol, runtime_checkable, ClassVar, Union

BenchValue = Union[int, float, str, bool]


@runtime_checkable
class PolicyProtocol(Protocol):
    """
    Minimal benchmarkable hashing policy contract.

    All concrete hashing policies must supply:
      - ENV_PREFIX
      - BENCH_SCHEMA (may be {})
      - to_dict()
    """
    ENV_PREFIX: ClassVar[str]
    BENCH_SCHEMA: ClassVar[dict[str, list[BenchValue]]]

    def to_dict(self) -> dict[str, object]: ...
