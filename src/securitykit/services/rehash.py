from __future__ import annotations
from dataclasses import dataclass
from typing import Protocol

from securitykit.runtime import get_factory


class RehashListener(Protocol):
    def on_rehash(self, old_hash: str, new_hash: str) -> None: ...


@dataclass
class RehashResult:
    valid: bool
    rehashed: bool
    new_hash: str | None


def verify_and_optionally_rehash(
    stored_hash: str,
    password: str,
    *,
    auto_rehash: bool = True,
    listener: RehashListener | None = None,
) -> RehashResult:
    """
    Verifiera lösenord, kontrollera om rehash behövs, och ev. generera en ny.

    Returnerar:
      valid: om lösenordet matchade
      rehashed: om ny hash genererades
      new_hash: ny hash eller None
    """
    factory = get_factory()
    hasher = factory.get_hasher()

    if not hasher.verify(stored_hash, password):
        return RehashResult(valid=False, rehashed=False, new_hash=None)

    if auto_rehash and hasher.needs_rehash(stored_hash):
        new_hash = hasher.hash(password)
        if listener:
            listener.on_rehash(stored_hash, new_hash)
        return RehashResult(valid=True, rehashed=True, new_hash=new_hash)

    return RehashResult(valid=True, rehashed=False, new_hash=None)
