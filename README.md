# SecurityKit

SecurityKit is a modular Python toolkit for secure, evolvable password handling:

- Modern password hashing (algorithms opt‑in via extras; conditional registration)
- Centralized pepper subsystem (config‑driven strategies, cryptographic HMAC mode)
- Password complexity policies, strength evaluation, and validation
- Deterministic config → object pipeline (env/mapping → validated dataclasses)
- Benchmark framework for tuning hash parameters (manual or auto bootstrap)
- Safe bootstrap with integrity protection (and PEPPER_* exclusion)
- High test coverage, minimal global state, explicit extension points

---

## Table of Contents

1. Design Principles  
2. Installation  
3. High‑Level Architecture  
4. Module Map  
5. Pepper Subsystem Overview  
6. Hashing Subsystem  
7. Password Policies & Validation  
8. Configuration Loader  
9. Benchmarking & Auto Bootstrap  
10. Public API (`securitykit.api`)  
11. Quick Start Examples  
12. Rehash & Migration Workflows  
13. Extensibility (Policies / Algorithms / Pepper)  
14. Configuration Reference  
15. Security Considerations  
16. Testing & Development Workflow  
17. Roadmap  
18. Contributing  
19. License  

---

## 1. Design Principles

| Principle        | Applied As |
|------------------|------------|
| Explicitness     | Registries & factories are opt‑in; discovery is idempotent |
| Determinism      | Config parsing, benchmarking, pepper application are pure and reproducible |
| Centralization   | Pepper logic lives in one subsystem (no duplicated per‑algorithm code) |
| Isolation        | Global mutable state limited to small registries with snapshot/restore in tests |
| Extensibility    | New algorithms/policies/pepper strategies via lightweight decorators |
| Observability    | Warnings for weak params, structured logs, integrity hash on generated configs |
| Fail Fast        | Aggregated configuration validation errors; no half‑configured states |
| Testability      | Narrow façades, pure conversions, registry‑driven parametrization |
| Evolvability     | `needs_rehash` + login‑time upgrade; safe parameter raises |

---

## 2. Installation

- Python: >= 3.10

Minimal core (no crypto libraries by default):
```bash
pip install securitykit
```

Opt‑in algorithms via extras:
- Argon2: `pip install "securitykit[alg_argon2]"`
- bcrypt: `pip install "securitykit[alg_bcrypt]"`
- Werkzeug PBKDF2: `pip install "securitykit[alg_werkzeug]"`

Development (run full test suite with all extras):
```bash
pip install -e ".[dev]"
```

Notes:
- Algorithms register conditionally based on what’s installed; the registry reflects your environment.
- In CI, install the dev extra to run the full algorithm matrix.

---

## 3. High‑Level Architecture

```
securitykit/
  api/                   (Stable public surface; lazy symbol resolution)
  hashing/
    algorithm.py         (Façade: pepper + guards + error wrapping + cross-variant tolerance)
    algorithms/          (Raw implementations: hash_raw / verify_raw / needs_rehash)
    policies/            (Policy dataclasses + BENCH_SCHEMA)
    *registry.py         (Algorithm / policy registries)
    factory.py           (Config → policy + façade)
    utils.py             (detect_variant and helpers)
  transform/pepper/      (Pepper strategies, builder, pipeline)
  password/              (Policy, Validator, Strength Evaluator, Factory)
  utils/config_loader/   (Deterministic config → object infrastructure)
  bench/                 (Benchmark enumerator, engine, analyzer, CLI)
  bootstrap.py           (Auto benchmark + integrity‑protected env generation)
```

Typical control flow:

```
password → PasswordValidator → Pepper Pipeline (if enabled) → Algorithm façade
         → algorithm hash_raw/verify_raw → underlying crypto library → encoded hash
```

---

## 4. Module Map (Public vs. Internal)

| Layer | Public Import | Notes |
|-------|---------------|-------|
| High‑level API | `securitykit.api` | Stable; lazy loader |
| Hash façade | `securitykit.hashing.Algorithm` | Direct for custom flows |
| Policies | `securitykit.hashing.policies.<variant>.*Policy` | Frozen dataclasses |
| Password | `securitykit.password` (`PasswordPolicy`, `PasswordValidator`) | Complexity + validation |
| Pepper | `securitykit.transform.pepper` | Usually implicit via façade |
| Benchmark | `python -m securitykit.bench.cli` | Optional tuning/export |
| Config loader | `securitykit.utils.config_loader` | Deterministic mapping→typed |
| Bootstrap | `securitykit.bootstrap.ensure_env_config()` | One‑shot generation path |

---

## 5. Pepper Subsystem Overview

Config‑driven transformations applied exactly once before hashing:

| Mode            | Transformation                               | Strength |
|-----------------|----------------------------------------------|----------|
| `noop`          | identity                                     | – |
| `prefix`        | `prefix + password`                          | Obfuscation |
| `suffix`        | `password + suffix`                          | Obfuscation |
| `prefix_suffix` | Wrap with prefix and suffix                  | Obfuscation |
| `interleave`    | Insert token every N chars                   | Weak obfuscation |
| `hmac`          | `hex(HMAC(key, password))`                   | Cryptographic |

Only `hmac` provides cryptographic strengthening. Generated benchmark configs exclude all `PEPPER_*` keys on purpose.

---

## 6. Hashing Subsystem

- Unified façade: `Algorithm(variant: str, policy: Policy, config: Mapping[str, Any] | None = None)`
  - Applies pepper (if enabled)
  - Rejects empty passwords
  - Delegates to raw implementation (`hash_raw`, `verify_raw`, `needs_rehash`)
  - Centralizes cross‑variant tolerance (verifying a foreign hash returns `False`)
- Built‑in variants (optional via extras):
  - Argon2 (`variant="argon2"`) via `argon2‑cffi`
  - bcrypt (`variant="bcrypt"`)
  - scrypt (`variant="scrypt"`) via `hashlib.scrypt` (no extra dependency)
  - Werkzeug PBKDF2 (`variant="werkzeug_pbkdf2"`)
- Registries (case‑insensitive):
  - `register_algorithm("argon2")`, `register_algorithm("bcrypt")`, etc.
  - `register_policy("argon2")`, `register_policy("bcrypt")`, `register_policy("scrypt")`, `register_policy("werkzeug_pbkdf2")`
- Policies may declare `BENCH_SCHEMA` for tuning (Cartesian enumeration)
- Rehash logic:
  - Argon2: `PasswordHasher.check_needs_rehash`
  - bcrypt: parse cost factor vs. policy rounds
  - scrypt: decode `$scrypt$ln=...,r=...,p=...$...` and compare vs. policy
  - Werkzeug PBKDF2: parse `pbkdf2:sha256:ITERATIONS$...` and compare vs. policy

---

## 7. Password Policies & Validation

- `PasswordPolicy` dataclass fields (examples):
  - `min_length`
  - `require_upper/lower/digit/special` (hard checks)
  - `complexity_rule` (1–5) and `complexity_min_length` (soft scoring)
- `PasswordStrengthEvaluator` computes a 5‑bit mask across:
  - length (≥ `complexity_min_length`), upper, lower, digit, special
- `PasswordValidator` runs:
  1) hard checks (min/max, required classes), then  
  2) complexity threshold (≥ `complexity_rule` of 5)

Violations raise domain exceptions; invalid input is never hashed.

---

## 8. Configuration Loader

Deterministic pipeline for mapping → typed object:

Parsing order (heuristic):
1. Non‑strings unchanged
2. Booleans: `true/false/on/off/yes/no`
3. Sizes: `64k`, `32M`, `1G`, `8kb` (binary multiples)
4. Int pattern
5. Float pattern
6. Lists: split on `,` or `;`
7. Fallback: stripped string

Second pass enforces primitive types (int/float/bool) with aggregated errors.
`export_schema(cls, prefix)` produces metadata for docs/automation.

---

## 9. Benchmarking & Auto Bootstrap

Benchmark flow:
1. Enumerate combinations from `BENCH_SCHEMA`
2. Time hashing (median/min/max/stddev)
3. Filter candidates near target (± tolerance)
4. Pick balanced (variance of normalized positions) or closest
5. Output best config and optionally export `.env`

Auto bootstrap (`ensure_env_config()`):
- Loads `.env` and `.env.local`
- Validates integrity hash if present
- Checks required keys for selected variant (`HASH_VARIANT`)
- If incomplete & `AUTO_BENCHMARK=1` & policy has `BENCH_SCHEMA`:
  - run benchmark (pepper neutralized), write `.env.local` with:
    - tuned parameters
    - `GENERATED_BY`
    - `GENERATED_SHA256`
- Concurrency safe (file lock if `portalocker`)
- Pepper keys are always excluded from generated files

---

## 10. Public API (`securitykit.api`)

Lazy, stable export surface:

| Symbol | Purpose |
|--------|---------|
| `hash_password` / `verify_password` / `rehash_password` | High‑level functional interface |
| `authenticate_and_upgrade` | Login‑time verify + migrate (cross‑variant) |
| `Algorithm` | Hash façade (advanced/manual flows) |
| `HashingFactory` | Build façade from config mapping |
| `register_algorithm` / `list_algorithms` / `get_algorithm_class` | Algorithm registry |
| `register_policy` / `list_policies` / `get_policy_class` | Policy registry |
| `Argon2Policy`, `BcryptPolicy`, `ScryptPolicy`, `WerkzeugPBKDF2Policy` | Built‑in policies |
| `PasswordPolicy`, `PasswordValidator` | Password complexity subsystem |

Variants are conditionally registered based on installed extras.

---

## 11. Quick Start Examples

### Hash + Verify (Functional)
```python
from securitykit.api import hash_password, verify_password
h = hash_password("StrongExample1!")
assert verify_password("StrongExample1!", h)
```

### Rehash Path (same variant)
```python
from securitykit.api import verify_password, rehash_password
if verify_password(candidate, stored_hash):
    new_hash = rehash_password(candidate, stored_hash)
    if new_hash != stored_hash:
        persist_new_hash(new_hash)
```

### Cross‑Variant Login Upgrade (e.g., bcrypt → Argon2)
```python
from securitykit.api import authenticate_and_upgrade
dest_cfg = {"HASH_VARIANT": "argon2", "ARGON2_TIME_COST": 3, "ARGON2_MEMORY_COST": 131072, "ARGON2_PARALLELISM": 2}
ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
if ok and new_hash is not None:
    persist_new_hash(new_hash)
```

### Manual Façade + Policy
```python
from securitykit.hashing import Algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy

policy = Argon2Policy(time_cost=3, memory_cost=64*1024, parallelism=2)
algo = Algorithm("argon2", policy)
digest = algo.hash("Password123!")
assert algo.verify(digest, "Password123!")
```

### Pepper (HMAC)
```python
import os
os.environ["PEPPER_MODE"] = "hmac"
os.environ["PEPPER_HMAC_KEY"] = "Random32BytesOrBetter"
from securitykit.api import hash_password
h = hash_password("SensitivePass1!")
```

---

## 12. Rehash & Migration Workflows

- Same‑variant policy raise:
  1) Verify password
  2) If `needs_rehash=True`, rehash and persist

- Cross‑variant migration (e.g., Werkzeug PBKDF2 → Argon2):
  - Use `authenticate_and_upgrade(password, stored_hash, config=dest_cfg)`
  - On success, a new hash for the destination variant is returned; persist it

Façade ensures verifying a foreign variant returns `False` (no exceptions from underlying libs).

---

## 13. Extensibility (Policies / Algorithms / Pepper)

### New Policy
```python
from dataclasses import dataclass, asdict
from securitykit.hashing.policy_registry import register_policy

@register_policy("scrypt")
@dataclass(frozen=True)
class ScryptPolicy:
    ENV_PREFIX: str = "SCRYPT_"
    BENCH_SCHEMA = {"n": [2**13, 2**14], "r": [8], "p": [1, 2]}
    n: int = 2**13
    r: int = 8
    p: int = 1
    salt_length: int = 16
    hash_length: int = 32
    def to_dict(self): return asdict(self)
    def __post_init__(self): ...
```

### New Raw Algorithm (conditional registration)
```python
try:
    import some_lib
    _AVAILABLE = True
except Exception:
    some_lib = None
    _AVAILABLE = False

from securitykit.hashing.algorithm_registry import register_algorithm
from .policies.myalgo import MyAlgoPolicy

if _AVAILABLE:
    @register_algorithm("myalgo")
    class MyAlgo:
        DEFAULT_POLICY_CLS = MyAlgoPolicy
        def __init__(self, policy: MyAlgoPolicy | None = None): ...
        def hash_raw(self, peppered_password: str) -> str: ...
        def verify_raw(self, stored_hash: str, peppered_password: str) -> bool: ...
        def needs_rehash(self, stored_hash: str) -> bool: ...
```

### New Pepper Strategy
```python
from dataclasses import dataclass
from securitykit.transform.pepper.core import register_strategy

@register_strategy("reverse")
@dataclass(frozen=True)
class ReverseStrategy:
    def apply(self, password: str) -> str:
        return password[::-1]
```

---

## 14. Configuration Reference

Core hashing:
```
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16

# bcrypt
BCRYPT_ROUNDS=12

# scrypt
SCRYPT_N=16384
SCRYPT_R=8
SCRYPT_P=1
SCRYPT_SALT_LENGTH=16
SCRYPT_HASH_LENGTH=32
# OpenSSL memory cap (bytes); default 512 MiB if unset
SCRYPT_MAXMEM=536870912

# Werkzeug PBKDF2
WERKZEUG_PBKDF2_METHOD=pbkdf2:sha256
WERKZEUG_PBKDF2_ITERATIONS=260000
WERKZEUG_PBKDF2_SALT_LENGTH=16
```

Password policy:
```
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
# Soft complexity scoring
PASSWORD_COMPLEXITY_RULE=3          # 1..5
PASSWORD_COMPLEXITY_MIN_LENGTH=12   # contributes to score
```

Pepper:
```
PEPPER_ENABLED=true
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=<secret>
PEPPER_HMAC_ALGO=sha256
# Alternative modes: prefix, suffix, prefix_suffix, interleave (+ related keys)
```

Bootstrap / Benchmark:
```
AUTO_BENCHMARK=0
AUTO_BENCHMARK_TARGET_MS=250
SECURITYKIT_DISABLE_BOOTSTRAP=0
SECURITYKIT_ENV=development
```

Generated metadata (by bootstrap):
```
GENERATED_BY=securitykit-bench vX.Y.Z
GENERATED_SHA256=<integrity-hash>
```

---

## 15. Security Considerations

| Aspect | Treatment | Notes |
|--------|-----------|-------|
| Pepper | Central strategy; only HMAC is cryptographically strong | Non‑HMAC modes are structured obfuscation |
| Hash Parameters | Policies validated; warnings for low settings | Raise values over time + rehash |
| Rehash Safety | Conditional rehash after successful verify | Avoids forced migrations |
| Integrity of Generated Config | SHA256 over key=value lines | Warn on tampering |
| Configuration Validation | Aggregated, typed errors | Prevent partial misconfig |
| Empty Passwords | Rejected by façade | No silent empty hashes |
| Cross‑Variant Verify | Central tolerance returns `False` | No leaking library exceptions |
| Logging | Warnings for weak/legacy params | Operational visibility |

---

## 16. Testing & Development Workflow

Run everything:
```bash
make test
```

Common loops:
```bash
pytest -k hashing -q
pytest --cov=src --cov-report=term-missing
```

Notes:
- DRY fixtures and registry snapshots make tests deterministic
- Benchmark tests keep candidate grids small and timing stubs deterministic
- Install `.[dev]` to run full algorithm matrix locally/CI

---

## 17. Roadmap

| Item | Status | Notes |
|------|--------|-------|
| scrypt (hashlib) | Shipped | Resource‑friendly defaults; `SCRYPT_MAXMEM` control |
| Werkzeug PBKDF2 | Shipped | Optional extra; iterations parsed for rehash |
| Login‑time migration | Shipped | `authenticate_and_upgrade` helper |
| Pepper rotation (`PEPPER_VERSION`) | Planned | Dual verification window |
| Weighted benchmark scoring | Planned | Heuristic tuning |
| Observability hooks (metrics) | Planned | Hash counts, rehash events |
| Async façade | Investigating | ASGI/non‑blocking |
| Hardware advisory heuristics | Planned | Param guidance based on host |
| Per‑user derived pepper (HKDF) | Planned | Minimize blast radius |

---

## 18. Contributing

1. Create a feature/fix branch: `feat/<topic>` or `fix/<issue>`
2. Implement with tests (keep/improve coverage)
3. Document new public symbols (README / subsystem docs)
4. Run lint/type checks and tests locally
5. Submit PR with rationale, benchmarks (if param changes), and migration notes

---

## 19. License

MIT – see [LICENSE](./LICENSE).

---

### Minimal Reference Table

| Task | Import / Command |
|------|------------------|
| Hash password | `from securitykit.api import hash_password` |
| Verify password | `from securitykit.api import verify_password` |
| Conditional rehash | `from securitykit.api import rehash_password` |
| Login‑time upgrade | `from securitykit.api import authenticate_and_upgrade` |
| Manual façade | `from securitykit.hashing import Algorithm` |
| Policy class | `from securitykit.hashing.policies.argon2 import Argon2Policy` |
| Password complexity | `from securitykit.password import PasswordPolicy, PasswordValidator` |
| Benchmark CLI | `python -m securitykit.bench.cli ...` |
| Bootstrap (manual) | `from securitykit.bootstrap import ensure_env_config` |
| Config loader (advanced) | `from securitykit.utils.config_loader import ConfigLoader` |

Questions or ideas?  
Open an issue with your environment constraints, target latency, variant(s), and pepper mode for tailored guidance.
