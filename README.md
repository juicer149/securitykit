# SecurityKit

A modular and extensible **password security toolkit** for Python.

It provides:
- Consistent APIs for **password hashing**
- **Global pepper support**
- **Password policy enforcement**
- Optional **auto-tuned Argon2** parameters via a benchmark engine
- Configuration via environment variables or plain dicts

---

## Features

### Algorithms
- Argon2id (`argon2-cffi`)
- Registry-driven plug‑in system (`@register_algorithm("name")`)
- Uniform `Algorithm` abstraction: `hash(password)`, `verify(hash, password)`, `needs_rehash(hash)`, callable alias
- Global pepper (applied orthogonally across algorithms if provided)

### Policies
- `Argon2Policy`:
  - Parameters: `time_cost`, `memory_cost` (KiB), `parallelism`, `hash_length`, `salt_length`
  - Enforces hard minimums; warns if below OWASP-aligned baselines
- `PasswordPolicy`:
  - Complexity rules (length, uppercase, lowercase, digit, special)
  - Warnings if below recommended length (e.g. < 12)
  - Standalone (not in PolicyRegistry) – always importable directly

### Factory
- `SecurityFactory` builds:
  - Hashing algorithm instance (based on `HASH_VARIANT`)
  - Password policy instance (from env or defaults)
- Reads environment variables (e.g. `ARGON2_TIME_COST`, `PASSWORD_MIN_LENGTH`, `PEPPER_VALUE`)

### Benchmarking
- `make bench` (Click + tqdm) enumerates Argon2 parameter combinations
- Selects a configuration near a target runtime (default 250 ms)
- Writes `.env.local` (if requested) with `HASH_VARIANT` + tuned params
- Balanced selection prefers (within target window):
  - Adequate memory
  - Reasonable parallelism (without overloading CPU)

### Extensibility
- Add algorithms:
  ```python
  @register_algorithm("bcrypt")
  class BcryptAlgorithm: ...
  ```
- Add policies:
  ```python
  @register_policy("argon2")
  class Argon2Policy: ...
  ```
- `PasswordPolicy` intentionally not registered (used explicitly at app layer)

---

## Installation

```bash
# Clone (if developing locally)
git clone https://github.com/yourname/securitykit.git
cd securitykit

# Create virtual env + install with dev + bench extras
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
print(argon2.verify(password_hash, "WrongPass"))      # False

if argon2.needs_rehash(password_hash):
    password_hash = argon2.hash("MySecretPass!")  # migrate to stronger params
```

### Enforcing Password Policy

```python
from securitykit import PasswordPolicy, InvalidPolicyConfig

policy = PasswordPolicy(min_length=12, require_upper=True, require_digit=True)
policy.validate("StrongPass123!")      # OK
policy.validate("weak")                # raises InvalidPolicyConfig
```

### Using SecurityFactory + .env

`.env` (or `.env.local`):
```env
HASH_VARIANT=argon2
ARGON2_TIME_COST=6
ARGON2_MEMORY_COST=131072
ARGON2_PARALLELISM=4
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16

PEPPER_VALUE=supersecretpepper

PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
```

Code:
```python
import os
from dotenv import load_dotenv
from securitykit import SecurityFactory

load_dotenv()  # loads both .env and .env.local (if present)

factory = SecurityFactory(dict(os.environ))

hasher = factory.get_algorithm()
phash = hasher.hash("AnotherPass!")
assert hasher.verify(phash, "AnotherPass!")

pwd_policy = factory.get_password_policy()
pwd_policy.validate("AnotherPass!")

# Example login-time rehash upgrade:
def authenticate(password: str, stored_hash: str):
    if not hasher.verify(stored_hash, password):
        return False
    if hasher.needs_rehash(stored_hash):
        new_hash = hasher.hash(password)
        # persist new_hash to DB
    return True
```

---

## Benchmarking

Tune Argon2 parameters to approximately a target runtime (default 250 ms):

```bash
make bench
```

Pass options:
```bash
make bench ARGS="--variant argon2 --target-ms 400 --tolerance 0.15 --export-file .env.local"
```

Arguments:
| Flag | Purpose | Default |
|------|---------|---------|
| `--variant` | Hash variant | argon2 |
| `--target-ms` | Target hash time | 250 |
| `--tolerance` | ± tolerance fraction | 0.10 |
| `--rounds` | Timing rounds per combo | 3 |
| `--export-file` | Write best config to file | (none) |

Note: The benchmark currently enumerates time/memory/parallelism. `hash_length` and `salt_length` are not auto-tuned (set manually).

---

### Bootstrap & Auto-Benchmarking

SecurityKit can bootstrap hashing configuration automatically.

Sequence:
1. Load `.env`
2. Load `.env.local` (override)
3. Determine `HASH_VARIANT` (default: `argon2`)
4. Check required keys (derived from the selected policy's `BENCH_SCHEMA`)
5. If missing and `AUTO_BENCHMARK=1` → run benchmark → write `.env.local`
6. Add:
   - `GENERATED_BY`
   - `GENERATED_SHA256` (integrity signature)

Environment variables:
| Variable | Default | Description |
|----------|---------|-------------|
| `HASH_VARIANT` | argon2 | Selected hash variant |
| `AUTO_BENCHMARK` | 0 | Enable automatic tuning |
| `AUTO_BENCHMARK_TARGET_MS` | 250 | Target runtime (ms) |
| `SECURITYKIT_DISABLE_BOOTSTRAP` | 0 | Disable bootstrap entirely |
| `SECURITYKIT_ENV` | development | Adjusts log severity for missing config |

Recommendations:
- Production: Provide explicit, versioned configuration; keep auto benchmark disabled.
- Development: Temporarily set `AUTO_BENCHMARK=1` → let it generate `.env.local` → do not commit the generated file.

---

## Password Policy Environment Variables

| Variable | Purpose | Example |
|----------|---------|---------|
| `PASSWORD_MIN_LENGTH` | Minimum length | 12 |
| `PASSWORD_REQUIRE_UPPER` | Require uppercase | true |
| `PASSWORD_REQUIRE_LOWER` | Require lowercase | true |
| `PASSWORD_REQUIRE_DIGIT` | Require a digit | true |
| `PASSWORD_REQUIRE_SPECIAL` | Require symbol | true |

---

## Security Notes

- Keep `PEPPER_VALUE` out of source control (inject via deploy environment).
- Rotating the pepper requires rehash strategy (e.g., force login re-validation + rehash).
- Monitor Argon2 runtime over time; if hardware changes, re-benchmark intentionally (do not auto in prod).
- Avoid setting excessively high memory or time costs in multi-tenant environments → potential DoS factor.

---

## Roadmap

- [ ] Additional algorithms (bcrypt, scrypt, PBKDF2)
- [ ] JSON export for benchmark results
- [ ] Multi-phase adaptive benchmarking
- [ ] Framework helpers (Flask / FastAPI)
- [ ] Rehash convenience helper `rehash(password, stored_hash)`
- [ ] KDF utilities (e.g. Argon2 for symmetric key derivation)
- [ ] Variant comparison command (e.g. argon2 vs bcrypt timing)

---

## Running Tests

```bash
make test
```

---

## License

MIT – see [LICENSE](./LICENSE).

---
