from __future__ import annotations
import time
from statistics import mean

def measure_once(fn) -> float:
    t0 = time.perf_counter()
    fn()
    t1 = time.perf_counter()
    return (t1 - t0) * 1000.0  # ms

def measure(fn, warmup: int = 1, runs: int = 2) -> float:
    # warmup
    for _ in range(warmup):
        fn()
    samples = [measure_once(fn) for _ in range(runs)]
    return mean(samples)
