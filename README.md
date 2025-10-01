# SecurityKit

A modular and extensible **password security toolkit** for Python.

It provides:
- Consistent APIs for **password hashing**
- **Global pepper support**
- **Password policy enforcement**
- Optional **auto-tuned parameters** (via a benchmark engine)
- Configuration via environment variables or plain dicts
- Flexible **registry system** for algorithms and policies

---

## Features

### Algorithms
- Argon2id (`argon2-cffi`) included by default
- Registry-driven plug-in system (`@register_algorithm("name")`)
- Uniform `Algorithm` abstraction:  
  - `hash(password)`  
  - `verify(hash, password)`  
  - `needs_rehash(hash)`  
  - callable alias for convenience  
- Global pepper (orthogonal to algorithms, if provided)

### Policies
- **Argon2Policy**:
  - Parameters: `time_cost`, `memory_cost`, `parallelism`, `hash_length`, `salt_length`
  - Enforces hard minimums; warns if below OWASP-aligned baselines
- **PasswordPolicy**:
  - Complexity rules (length, uppercase, lowercase, digit, special)
  - Warnings if below recommended length (e.g. < 12)
  - Standalone (not in the registry) – always importable directly

### Registry
- Unified `Registry` utility (`core/registry.py`)  
- Auto-discovery of all algorithms and policies via `load_all()`
- Prevents duplicate registration, validates policy/algorithm interfaces

### Factory
- `SecurityFactory` builds:
  - Hashing algorithm instance (based on `HASH_VARIANT`)
  - Password policy instance (from env or defaults)
- Reads environment variables (`ARGON2_TIME_COST`, `PASSWORD_MIN_LENGTH`, `PEPPER_VALUE`, etc.)

### Benchmarking
- Fully modular benchmarking subsystem (`bench/`):
  - Enumerates parameter combinations (`BENCH_SCHEMA`)
  - Runs timing benchmarks (`BenchmarkEngine`)
  - Selects the best config using `ResultAnalyzer` (closest vs balanced)
  - `BenchmarkRunner` orchestrates collection + analysis
- CLI via `python -m securitykit.bench.cli`
- Exports `.env.local` with best config and integrity metadata

### Extensibility
- Add algorithms:
  ```python
  @register_algorithm("bcrypt")
  class BcryptAlgorithm: ...
````

* Add policies (must define `BENCH_SCHEMA` for benchmarking):

  ```python
  @register_policy("bcrypt")
  class BcryptPolicy:
      BENCH_SCHEMA = {"cost": [10, 12, 14]}
  ```
* Automatically picked up by `load_all()`

---

## Installation

```bash
git clone https://github.com/yourname/securitykit.git
cd securitykit
make install
```

(Planned PyPI: `pip install securitykit`)

Requires **Python 3.10+**.

---

## Quick Start

### Hashing with Argon2

```python
from securitykit import Algorithm, Argon2Policy

policy = Argon2Policy(time_cost=6, memory_cost=131072, parallelism=4)
argon2 = Algorithm("argon2", policy, pepper="supersecretpepper")

password_hash = argon2.hash("MySecretPass!")
print(argon2.verify(password_hash, "MySecretPass!"))  # True
```

### Enforcing Password Policy

```python
from securitykit import PasswordPolicy

policy = PasswordPolicy(min_length=12, require_upper=True, require_digit=True)
policy.validate("StrongPass123!")  # OK
policy.validate("weak")            # raises InvalidPolicyConfig
```

---

## Benchmarking & Bootstrap

### Manual Benchmark

```bash
python -m securitykit.bench.cli --variant argon2 --target-ms 300 --export-file .env.local
```

### Auto-Bootstrap

At import, SecurityKit will:

1. Load `.env` and `.env.local`
2. Verify integrity via `GENERATED_SHA256`
3. Ensure required keys are present (from the selected policy’s `BENCH_SCHEMA`)
4. If missing and `AUTO_BENCHMARK=1`, run a benchmark and regenerate `.env.local`
5. Lock `.env.local` during generation to avoid race conditions

---

## Roadmap

* [ ] Additional algorithms (bcrypt, scrypt, PBKDF2)
* [ ] JSON export for benchmark results
* [ ] Adaptive multi-phase benchmarking
* [ ] Framework helpers (Flask / FastAPI)
* [ ] Rehash helper for transparent upgrades

---

## Running Tests

```bash
make test
```

---

## License

MIT – see [LICENSE](./LICENSE).
