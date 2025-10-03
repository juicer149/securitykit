# SecurityKit Benchmarking

The `securitykit.bench` package provides tooling to explore hashing policy parameter
spaces (defined via `BENCH_SCHEMA`), time each combination, and select a configuration
that meets a target latency envelope (e.g. ~250 ms per hash under load).

It is optional: production usage can set parameters statically; benchmarking helps you
derive balanced values per deployment environment.

---

## Contents

1. Goals  
2. Conceptual Flow  
3. Core Components  
4. Pepper & Benchmarking  
5. Python Usage  
6. CLI Usage  
7. Selection Strategies  
8. Exporting Results  
9. Integration With Bootstrap / AUTO_BENCHMARK  
10. Making a Policy Benchmarkable  
11. Reproducibility & Best Practices  
12. Extending & Future Enhancements  

---

## 1. Goals

| Goal | Description |
|------|-------------|
| Parameter Exploration | Try all combinations defined in `BENCH_SCHEMA` |
| Latency Targeting | Choose config near a requested target ms |
| Balanced Selection | Prefer evenly distributed parameters (not always “all maxed”) |
| Deterministic Export | Emit `.env` lines for reuse |
| Non‑intrusive | Can be disabled entirely (no forced side effects) |

---

## 2. Conceptual Flow

```
BENCH_SCHEMA (policy)
   ↓ enumerate combinations
BenchmarkEngine (measure median over N rounds)
   ↓ produce BenchmarkResult set
ResultAnalyzer (filter_near → balanced OR closest)
   ↓ best configuration
export_env → .env lines (HASH_VARIANT + parameter keys)
```

---

## 3. Core Components

| Component | Responsibility |
|-----------|----------------|
| `BenchmarkConfig` | Holds variant, target ms, tolerance, rounds; resolves policy class + schema |
| `PolicyEnumerator` *(internal)* | Cartesian product of `BENCH_SCHEMA` dimensions |
| `BenchmarkEngine` | Times hashing for a given policy instance (`hash_raw` via façade) |
| `BenchmarkResult` | Immutable stats (median / min / max / stddev / delta) |
| `ResultAnalyzer` | Selection helpers: `filter_near`, `closest`, `balanced` |
| `BenchmarkRunner` | Orchestrates enumeration, timing, selection |
| `export_env` | Writes chosen configuration to file |
| CLI (`bench/cli.py`) | User-facing interface for ad‑hoc benchmarks |

---

## 4. Pepper & Benchmarking

The Algorithm façade always applies pepper (via `PEPPER_*`) if enabled.

For *consistent* performance measurement you typically want to neutralize pepper:

```python
neutral_config = {"PEPPER_ENABLED": "false"}
algo = Algorithm("argon2", policy=my_policy, config=neutral_config)
```

The current benchmarking code does **not** inject a special pepper config, so:
- If your environment sets `PEPPER_MODE=hmac`, the timing cost includes HMAC overhead.
- To isolate raw hash cost, run benchmarks with `PEPPER_ENABLED=false`.

Exported benchmark configs intentionally exclude `PEPPER_*` keys (hash cost tuning
should reflect the underlying algorithm; pepper can be layered afterwards).

---

## 5. Python Usage

```python
from securitykit.bench.config import BenchmarkConfig
from securitykit.bench.runner import BenchmarkRunner

cfg = BenchmarkConfig(variant="argon2", target_ms=250, tolerance=0.15, rounds=5)
runner = BenchmarkRunner(cfg)
result = runner.run()

best = result["best"]          # dict -> env keys
best_result = result["best_result"]
near = result["near"]          # list[BenchmarkResult]
```

`best` example:

```python
{
  "HASH_VARIANT": "argon2",
  "ARGON2_TIME_COST": "3",
  "ARGON2_MEMORY_COST": "65536",
  "ARGON2_PARALLELISM": "2"
}
```

---

## 6. CLI Usage

```bash
python -m securitykit.bench.cli \
  --variant argon2 \
  --target-ms 250 \
  --tolerance 0.15 \
  --rounds 5 \
  --export-file .env.local
```

Steps performed:

1. Enumerate combinations from `BENCH_SCHEMA`.
2. Time median hashing cost for each.
3. Filter candidates within ± tolerance of target.
4. Pick balanced candidate (or closest if none are “near”).
5. Print and optionally export config.

Help:

```bash
python -m securitykit.bench.cli --help
```

---

## 7. Selection Strategies

`ResultAnalyzer` provides:

| Method | Purpose |
|--------|---------|
| `filter_near(results, target_ms, tolerance)` | Subset within `[target*(1−tol), target*(1+tol)]` |
| `closest(results, target_ms)` | Single result with minimal absolute deviation |
| `balanced(results)` | Lower variance across normalized dimension positions |

Balanced scoring treats each numeric dimension, normalizes the policy's value,
and computes a variance (lower = more “even”).

---

## 8. Exporting Results

API path:

```python
from securitykit.bench.bench import export_env
export_env(result["best"], ".env.argon2.tuned")
```

CLI path: `--export-file myfile.env`

Export only includes hashing parameter keys; pepper keys are intentionally excluded
to avoid “baking in” a secret state into versioned files.

---

## 9. Integration With Bootstrap / AUTO_BENCHMARK

If you enable a bootstrap layer that:
- Detects missing hashing env vars
- Sees `AUTO_BENCHMARK=1`
- Has a `BENCH_SCHEMA` for the selected variant

It can:
1. Run a benchmark automatically
2. Write a local `.env.local` with chosen values plus metadata (e.g. a hash)
3. Log a summary

You can opt out by unsetting `AUTO_BENCHMARK` or providing all required keys.

---

## 10. Making a Policy Benchmarkable

Add a `BENCH_SCHEMA`:

```python
BENCH_SCHEMA = {
    "time_cost": [2, 3, 4],
    "memory_cost": [65536, 131072],
    "parallelism": [1, 2],
}
```

Rules:
- Each key must map to a non‑empty list.
- All combinations are enumerated (Cartesian product).
- Avoid excessively large search spaces for production; prune values or pre‑filter.

---

## 11. Reproducibility & Best Practices

| Concern | Recommendation |
|---------|----------------|
| Pepper overhead | Run with `PEPPER_ENABLED=false` to isolate hashing cost |
| Noise | Use more rounds (e.g. `--rounds 7`) for stable medians |
| CI time | Reduce schema lists (e.g. 2 values per dimension) |
| System load | Run on a quiet machine or pinned CPU set |
| Memory variability | Avoid dynamic system pressure during runs |
| Multi‑tenant tuning | Benchmark per host class (store tuned sets separately) |

---

## 12. Extending & Future Enhancements

| Idea | Benefit |
|------|---------|
| Weighted scoring function injection | Tailor dimension priorities |
| Hardware introspection baseline | Auto‑suggest an initial schema subset |
| Parallel timing executor | Faster enumeration on multi‑core boxes |
| Persistence layer (JSON log) | Historical trend analysis |
| Confidence intervals | Discard outliers / variance thresholding |
| Schema pruning heuristics | Early elimination of dominated configs |

---

## 13. Examples (Short)

Programmatic only for a very small schema:

```python
cfg = BenchmarkConfig("argon2", target_ms=150, tolerance=0.10, rounds=3)
runner = BenchmarkRunner(cfg)
data = runner.run()
print("Best:", data["best"])
```

---

## 14. Notes

- Large Cartesian expansions can explode; keep dimension lists tight.
- For multi‑param algorithms (future scrypt) consider incrementally expanding ranges.
- Benchmarks measure password hashing only; they exclude pepper cost *if* you disable pepper.

---

## 15. License / Usage

Internal subsystem of SecurityKit. Prefer static tuning in production once stable.
Use exported `.env` files for deterministic deployments. Monitor logs when auto
benchmarking to ensure consistent performance.

---
