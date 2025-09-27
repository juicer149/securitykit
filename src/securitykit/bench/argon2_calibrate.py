from __future__ import annotations

import os
import time
import socket
import math
from dataclasses import dataclass
from typing import Optional

from argon2 import PasswordHasher
from securitykit.bench.utils import measure
from securitykit.bench.cache import (
    get_entry,
    save_entry,
    CalibrationEntry,
    DEFAULT_CACHE_PATH,
)
from securitykit.exceptions import SecurityKitError

@dataclass
class Argon2CalibrationResult:
    time_cost: int
    memory_cost: int
    parallelism: int
    measured_ms: float
    iterations: int
    limited: bool  # om vi slog i max gränser
    from_cache: bool = False
    reason: str = ""

def calibrate_argon2(
    *,
    target_lower_ms: int = 180,
    target_upper_ms: int = 320,
    max_iters: int = 15,
    max_memory_kib: int = 524288,   # 512 MB
    max_time_cost: int = 12,
    cache_path: Optional[str] = None,
    allow_cache: bool = True,
    force: bool = False,
    fast_fail_seconds: float = 5.0,
    enable_parallelism: bool = True,
) -> Argon2CalibrationResult:
    """
    Adaptiv kalibrering för Argon2.
    """
    cache_path = cache_path or os.environ.get("CALIBRATION_CACHE_PATH", DEFAULT_CACHE_PATH)
    cpu_count = os.cpu_count() or 1
    hostname = socket.gethostname()

    # Cache?
    if allow_cache and not force:
        cached = get_entry("argon2", cache_path)
        if cached:
            c_cpu = cached.get("cpu_count")
            # enkel heuristik: om CPU diff > 50% (t.ex. container-skillnad) -> kalibrera om
            if c_cpu and c_cpu > 0 and (abs(c_cpu - cpu_count) / c_cpu) <= 0.5:
                params = cached["params"]
                return Argon2CalibrationResult(
                    time_cost=params["time_cost"],
                    memory_cost=params["memory_cost"],
                    parallelism=params["parallelism"],
                    measured_ms=cached.get("measured_ms", -1),
                    iterations=0,
                    limited=False,
                    from_cache=True,
                    reason="cache hit",
                )

    start_wall = time.perf_counter()

    # Startvärden
    time_cost = 2
    memory_cost = 65536  # 64 MB
    parallelism = min(2, cpu_count) if enable_parallelism else 1

    best = None

    def measure_current() -> float:
        ph = PasswordHasher(
            time_cost=time_cost,
            memory_cost=memory_cost,
            parallelism=parallelism,
        )
        return measure(lambda: ph.hash("CalibratePassw0rd!"), warmup=1, runs=1)

    limited = False
    iteration = 0

    while iteration < max_iters:
        iteration += 1
        elapsed = measure_current()

        if target_lower_ms <= elapsed <= target_upper_ms:
            best = (time_cost, memory_cost, parallelism, elapsed, iteration, limited)
            break

        # För snabbt → öka kostnad
        if elapsed < target_lower_ms:
            if time_cost < max_time_cost:
                time_cost += 1
            elif memory_cost < max_memory_kib:
                # öka memory i samband med brandbredd, men kontrollera overflow
                memory_cost = min(int(memory_cost * 1.5), max_memory_kib)
            elif enable_parallelism and parallelism < cpu_count and parallelism < 4:
                parallelism += 1
            else:
                limited = True
                best = (time_cost, memory_cost, parallelism, elapsed, iteration, True)
                break
        else:
            # För långsam → sänk
            if memory_cost > 65536 * 2:
                memory_cost = max(65536, int(memory_cost / 2))
            elif time_cost > 2:
                time_cost = max(2, time_cost - 1)
            elif enable_parallelism and parallelism > 1:
                parallelism -= 1
            else:
                limited = True
                best = (time_cost, memory_cost, parallelism, elapsed, iteration, True)
                break

        if (time.perf_counter() - start_wall) > fast_fail_seconds and best:
            # Avbryt om vi redan fått ett “ok-ish” försök
            break

    if best is None:
        # fallback: använd sista kombinationen
        best = (time_cost, memory_cost, parallelism, elapsed, iteration, limited)

    (tc, mc, par, ms, iters, limited_flag) = best

    result = Argon2CalibrationResult(
        time_cost=tc,
        memory_cost=mc,
        parallelism=par,
        measured_ms=ms,
        iterations=iters,
        limited=limited_flag,
        from_cache=False,
        reason="calibrated",
    )

    # Cache
    if allow_cache:
        entry = CalibrationEntry(
            algo="argon2",
            params={"time_cost": tc, "memory_cost": mc, "parallelism": par},
            measured_ms=ms,
            cpu_count=cpu_count,
            hostname=hostname,
            created_at=time.time(),
            version="1",
        )
        save_entry(entry, cache_path)

    return result
