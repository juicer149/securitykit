from __future__ import annotations
import re

# Argon2 encoded hash pattern (argon2id, argon2i, argon2d)
ARGON2_RE = re.compile(
    r"^\$(argon2(?:id|i|d))\$v=\d+\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+)$"
)

# Bcrypt pattern: $2b$12$<22chars salt><31chars hash> (total 60 chars)
BCRYPT_RE = re.compile(r"^\$(2[abxy]?)\$(\d{2})\$.{53}$")


def parse_argon2(hash_str: str):
    """
    Parse an Argon2 hash and return a dict:
      {
        'variant': str,
        'memory_cost': int,
        'time_cost': int,
        'parallelism': int,
        'salt_b64': str,
        'hash_b64': str
      }
    Return None if the string does not match the expected format.
    """
    m = ARGON2_RE.match(hash_str)
    if not m:
        return None
    variant, mem, time, para, salt, digest = m.groups()
    return {
        "variant": variant,
        "memory_cost": int(mem),
        "time_cost": int(time),
        "parallelism": int(para),
        "salt_b64": salt,
        "hash_b64": digest,
    }


def parse_bcrypt(hash_str: str):
    """
    Parse a bcrypt hash and return:
      {
        'prefix': str,
        'rounds': int
      }
    or None if not a valid bcrypt hash.
    """
    m = BCRYPT_RE.match(hash_str)
    if not m:
        return None
    prefix, cost = m.groups()
    return {
        "prefix": prefix,
        "rounds": int(cost),
    }
