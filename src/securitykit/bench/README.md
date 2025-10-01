# SecurityKit Benchmarking

The `securitykit.bench` package provides tooling for benchmarking password hashing algorithms and automatically generating environment configurations.

## Overview

The benchmarking system is designed to:
- Explore parameter combinations defined in a policy's `BENCH_SCHEMA`.
- Measure average hashing times across those combinations.
- Select the configuration that is closest (and most balanced) to a target execution time (e.g. 250 ms).
- Optionally export the result to a `.env` file for use in bootstrapping.

This allows SecurityKit to auto-tune hashing parameters for a given environment, ensuring consistent security and performance across systems.

---

## Components

- **`BenchmarkConfig`**  
  Defines the configuration for a benchmark run (variant, target time, tolerance, number of rounds).

- **`BenchmarkEngine`**  
  Runs hashing measurements for a given policy and algorithm.

- **`BenchmarkResult`**  
  Immutable container for the timing results of a single policy configuration.

- **`ResultAnalyzer`**  
  Provides selection strategies (used internally by `BenchmarkRunner`):
  - `closest()` → closest to the target time.  
  - `filter_near()` → results within ± tolerance.  
  - `balanced()` → balances parameters across ranges (useful for multi-dimensional configs like Argon2).

- **`BenchmarkRunner`**  
  Orchestrates enumeration of all configurations, timing, and analysis. Produces the final result set including the "best" config.

- **`export_env()`**  
  Utility to write chosen configs into `.env` format.

- **CLI (`bench/cli.py`)**  
  A command-line interface powered by `click` to run benchmarks manually.

---

## Usage

### From Python
```python
from securitykit.bench.config import BenchmarkConfig
from securitykit.bench.runner import BenchmarkRunner

config = BenchmarkConfig(variant="argon2", target_ms=250, tolerance=0.15, rounds=5)
runner = BenchmarkRunner(config)
result = runner.run()

print("Best config:", result["best"])
````

### From CLI

```bash
python -m securitykit.bench.cli --variant argon2 --target-ms 250 --tolerance 0.15 --rounds 5 --export-file .env.local
```

This will:

1. Run benchmarks for the given algorithm variant (`argon2`).
2. Try all parameter combinations defined in its `BENCH_SCHEMA`.
3. Select the configuration that best matches the target time.
4. Export the configuration to `.env.local`.

👉 Tip: Run `python -m securitykit.bench.cli --help` to see all available options.

---

## Integration with Bootstrap

When SecurityKit is imported, the **bootstrap system** (`securitykit/bootstrap.py`) ensures that hashing parameters are available in the environment.
If they are missing or incomplete:

* And `AUTO_BENCHMARK=1` is set → a benchmark run is triggered.
* The resulting config is exported into `.env.local`.
* The file includes integrity metadata (`GENERATED_SHA256`) to prevent accidental modification.

---

## Extending

To make a new policy benchmarkable:

1. Define a `BENCH_SCHEMA` class variable in the policy, mapping parameter names to lists of candidate values.
2. Register the policy using `@register_policy`.
3. The benchmarking system will automatically pick it up.

Example:

```python
@register_policy("bcrypt")
class BcryptPolicy:
    BENCH_SCHEMA = {
        "cost": [10, 12, 14],
    }
```

For multi-parameter algorithms (e.g. scrypt), you can define multiple dimensions:

```python
@register_policy("scrypt")
class ScryptPolicy:
    BENCH_SCHEMA = {
        "n": [2**14, 2**15],
        "r": [8, 16],
        "p": [1, 2],
    }
```

Now you can run:

```bash
python -m securitykit.bench.cli --variant bcrypt
```

---

## Notes

* Benchmarking can take a while, depending on the parameter space.
* For CI testing, the benchmarking logic is often **mocked or short-circuited** to avoid long runtimes.
* Use `AUTO_BENCHMARK_TARGET_MS` to adjust the target time dynamically in production environments.
