from __future__ import annotations
import json
import os
import socket
import time
from dataclasses import dataclass
from typing import Any

DEFAULT_CACHE_PATH = os.path.join(
    os.path.expanduser("~"),
    ".cache",
    "securitykit",
    "calibration.json",
)

@dataclass
class CalibrationEntry:
    algo: str
    params: dict[str, Any]
    measured_ms: float
    cpu_count: int
    hostname: str
    created_at: float
    version: str = "1"

def load_cache(path: str = DEFAULT_CACHE_PATH) -> dict[str, Any] | None:
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        return None
    except Exception:
        return None

def ensure_dir(path: str):
    d = os.path.dirname(path)
    if not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)

def save_entry(entry: CalibrationEntry, path: str = DEFAULT_CACHE_PATH) -> None:
    ensure_dir(path)
    data = load_cache(path) or {}
    data[entry.algo] = {
        "params": entry.params,
        "measured_ms": entry.measured_ms,
        "cpu_count": entry.cpu_count,
        "hostname": entry.hostname,
        "created_at": entry.created_at,
        "version": entry.version,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def get_entry(algo: str, path: str = DEFAULT_CACHE_PATH):
    data = load_cache(path)
    if not data:
        return None
    return data.get(algo)
