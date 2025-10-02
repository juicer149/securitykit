# SecurityKit

SecurityKit is a modular Python toolkit for:

- Password hashing (currently Argon2id)
- Password complexity policies and validation
- Configuration → policy instantiation (env/dict → dataclass)
- Benchmark‑driven tuning of hashing parameters (auto or manual)
- Safe bootstrap of production‑ready defaults

The project emphasizes determinism, composability, and testability (high coverage).

---

## Architecture Overview

```
securitykit/
  api/                 High-level public API (hash_password, verify_password, rehash_password)
  hashing/             Algorithm abstraction, policies, registries (e.g. Argon2)
  password/            PasswordPolicy + PasswordValidator (complexity rules)
  utils/config_loader/ Generic config → object pipeline (prefix + parsing)
  bench/               Benchmark enumeration, timing engine, analyzer, CLI
  bootstrap.py         Auto configuration bootstrap + integrity validation
```

Core principles:

| Principle     | Applied As                                                       |
|---------------|------------------------------------------------------------------|
| Explicitness  | No hidden magic; registries and factories are opt-in             |
| Isolation     | Global state limited to registries; test suite snapshots safely |
| Extensibility | Register new algorithms/policies without modifying core code    |
| Observability | Warnings for defaults; structured logging for key events        |
| Determinism   | Config parsing and benchmarking paths are reproducible          |

---

## Feature Summary

### 1. Hashing Subsystem (`securitykit.hashing`)

- Algorithm abstraction: `Algorithm(variant, policy, pepper=None)`
- Built-in Argon2id implementation (via `argon2-cffi`)
- Registry-based discovery:
  - `@register_algorithm("argon2")`
  - `@register_policy("argon2")`
- Policy classes are dataclasses with optional `BENCH_SCHEMA` for tuning
- `needs_rehash(hash)` detects outdated parameter sets

### 2. Password Subsystem (`securitykit.password`)

- `PasswordPolicy` (min/max length bounds + flags: upper/lower/digit/special)
- Warnings if `min_length` below recommended baseline
- `PasswordValidator.validate(password)` enforces complexity rules

### 3. Configuration Loader (`securitykit.utils.config_loader`)

- Prefix-based parameter resolution (e.g. `ARGON2_TIME_COST`)
- Heuristic parsing:
  - Booleans (`true/false/on/off/yes/no`)
  - Numeric (int / float / negative)
  - Sizes (`64k`, `32M`, `1G`, plain bytes)
  - Lists (`,` or `;` separated)
- Aggregated error reporting (all missing/invalid keys in a single exception)
- Schema export utility for documentation / tooling integration

### 4. Benchmarking (`securitykit.bench`)

- Cartesian enumeration of `BENCH_SCHEMA` (e.g. time_cost × memory_cost × parallelism)
- Timing engine (multiple rounds, median/min/max/stddev)
- `ResultAnalyzer` strategies:
  - `filter_near(target, tolerance)`
  - `closest(target)`
  - `balanced()` (variance-based distribution across numeric dimensions)
- CLI runner (`python -m securitykit.bench.cli`)
- Export of tuned config → `.env.local`

### 5. Bootstrap (`securitykit/bootstrap.py`)

- Layered load: `.env` → `.env.local`
- Integrity check of generated file (`GENERATED_SHA256`)
- Detects incomplete hashing policy configuration
- If `AUTO_BENCHMARK=1`, runs benchmark and writes `.env.local`
- Safe concurrent generation (file lock if `portalocker` installed)

### 6. High-Level API (`securitykit.api`)

Import everything you typically need from one place:

```python
from securitykit.api import (
    hash_password,
    verify_password,
    rehash_password,
    PasswordPolicy,
    PasswordValidator,
)
```

API functions:

| Function           | Description                                        |
|--------------------|----------------------------------------------------|
| `hash_password(p)` | Validates via password policy, returns hash string |
| `verify_password(p, stored)` | Returns True/False                   |
| `rehash_password(p, stored)` | Returns new hash if parameters outdated |

### 7. Extensibility

Add a new algorithm:

```python
from dataclasses import dataclass
from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policy_registry import register_policy
from securitykit.hashing.algorithm import Algorithm
from securitykit.hashing.interfaces import AlgorithmProtocol

@register_policy("bcrypt")
@dataclass
class BcryptPolicy:
    cost: int = 12
    BENCH_SCHEMA = {"cost": [10, 12, 14]}

@register_algorithm("bcrypt")
class Bcrypt(AlgorithmProtocol):
    def __init__(self, policy: BcryptPolicy, pepper: str | None = None):
        ...
    def hash(self, password: str) -> str:
        ...
    def verify(self, stored: str, password: str) -> bool:
        ...
    def needs_rehash(self, stored: str) -> bool:
        ...
```

---

## Installation

```bash
git clone https://github.com/yourname/securitykit.git
cd securitykit
make install     # sets up virtualenv, dependencies
```

Requirements: **Python 3.10+**

(Planned: `pip install securitykit` after packaging.)

---

## Quick Start

### Hash + Verify

```python
from securitykit.api import hash_password, verify_password

# Ensure environment (or .env/.env.local) provides hashing params,
# or allow bootstrap to generate them if AUTO_BENCHMARK=1.

h = hash_password("Str0ngPass!")
assert verify_password("Str0ngPass!", h)
```

### Policy + Manual Algorithm Construction

```python
from securitykit.hashing import Algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy

policy = Argon2Policy(time_cost=3, memory_cost=65536, parallelism=2)
algo = Algorithm("argon2", policy, pepper="OPTIONAL_GLOBAL_PEPPER")

digest = algo.hash("Secret123!")
assert algo.verify(digest, "Secret123!")
if algo.needs_rehash(digest):
    digest = algo.hash("Secret123!")
```

### Password Validation

```python
from securitykit.password import PasswordPolicy, PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig

policy = PasswordPolicy(min_length=12, require_upper=True, require_digit=True)
validator = PasswordValidator(policy)

validator.validate("GoodPass123!")
try:
    validator.validate("weak")
except InvalidPolicyConfig:
    print("Rejected")
```

---

## Configuration

Typical environment variables (example Argon2):

```
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
AUTO_BENCHMARK=0
```

If any required Argon2 parameters are missing and `AUTO_BENCHMARK=1`, bootstrap runs a benchmark to populate `.env.local` and adds:

```
GENERATED_BY=securitykit-bench vX.Y.Z
GENERATED_SHA256=<integrity hash>
```

---

## Manual Benchmark

Tune parameters interactively:

```bash
python -m securitykit.bench.cli \
  --variant argon2 \
  --target-ms 250 \
  --tolerance 0.15 \
  --rounds 5 \
  --export-file .env.local
```

Outputs:
- Best configuration (closest or balanced inside tolerance)
- Near candidates (within ±tolerance)
- Optional export to `.env.local`

---

## Auto Bootstrap Flow Summary

On import (simplified):

1. Load `.env` (non-overriding)
2. Load `.env.local` (overriding)
3. Validate integrity (if `GENERATED_SHA256` present)
4. Check required BENCH_SCHEMA keys for chosen variant (`HASH_VARIANT`)
5. If incomplete:
   - If `AUTO_BENCHMARK=1` → run benchmark → export `.env.local`
   - Else → log warning (dev) or error (production)

---

## Configuration Loader (Internal Utility)

Conversion features: booleans, size (k/m/g), int, float, list (`,` or `;`), fallback to raw string.

Example:

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader

@dataclass
class Demo:
    size: int
    flags: list[str] | None = None
    enabled: bool = True

cfg = {
  "DEMO_SIZE": "64k",
  "DEMO_FLAGS": "a,b;c",
  "DEMO_ENABLED": "false",
}

policy = ConfigLoader(cfg).build(Demo, prefix="DEMO_", name="Demo")
assert policy.size == 65536
assert policy.flags == ["a","b","c"]
assert policy.enabled is False
```

---

## Testing

Run full suite (high coverage):

```bash
make test
```

Suggested developer workflow:

```bash
pytest -k hashing -q          # subset
pytest --maxfail=1 -q         # fast iteration
pytest --cov=src --cov-report=term-missing
```

---

## Security Considerations

| Aspect              | Current Handling                                  | Notes |
|---------------------|----------------------------------------------------|-------|
| Peppering           | Optional per-algorithm constructor param           | External secret management recommended |
| Parameter Bounds    | Policies enforce min/max & log warnings            | Hard errors for invalid ranges |
| Rehash Strategy     | `needs_rehash` central check                       | Call during login flows |
| .env Integrity      | `GENERATED_SHA256` for bootstrap-generated files   | Warns if modified manually |
| Timing Benchmarks   | Development / tuning only                          | Disable in production (“bake” values) |

---

## Roadmap

| Planned | Status |
|---------|--------|
| bcrypt / scrypt policies + algorithms | Pending |
| JSON / machine-readable benchmark export | Planned |
| Weighted / strategy-driven analyzer modes | Planned |
| Framework adapters (FastAPI/Flask) | Planned |
| Transparent on-access rehash wrapper | Planned |
| Layered config sources (env + file + remote) | Planned |

---

## Contributing

1. Fork / branch (`feat/...` or `refactor/...`)
2. Add or update tests (maintain coverage threshold)
3. Keep new public APIs documented in this README
4. Run linters / formatters (add pre-commit if contributing regularly)
5. Open PR with clear summary + rationale

---

## License

MIT – see [LICENSE](./LICENSE).

---

## Minimal References

| Import Need             | Use |
|-------------------------|-----|
| High-level hashing      | `from securitykit.api import hash_password` |
| Manual algorithm        | `from securitykit.hashing import Algorithm` |
| Password policy         | `from securitykit.password import PasswordPolicy` |
| Benchmark CLI           | `python -m securitykit.bench.cli ...` |
| Config loader (internal)| `from securitykit.utils.config_loader import ConfigLoader` |

---

**Questions / Ideas**: Open an issue or propose an extension via a draft PR.
