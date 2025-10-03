# SecurityKit

SecurityKit is a modular Python toolkit for secure, evolvable password handling:

- Modern password hashing (Argon2id built‑in; bcrypt present / future algorithms pluggable)
- Centralized pepper subsystem (config‑driven strategies, optional cryptographic HMAC mode)
- Password complexity policies + validation
- Deterministic config → object pipeline (env / mapping → validated dataclasses)
- Benchmark framework for tuning hash parameters (manual or auto bootstrap)
- Safe bootstrap with integrity protection
- High test coverage, minimal global state, explicit extension points

---

## Table of Contents

1. Design Principles  
2. High‑Level Architecture  
3. Module Map  
4. Pepper Subsystem Overview  
5. Hashing Subsystem  
6. Password Policies & Validation  
7. Configuration Loader  
8. Benchmarking & Auto Bootstrap  
9. Public API (`securitykit.api`)  
10. Quick Start Examples  
11. Rehash Workflow  
12. Extensibility (Adding Policies / Algorithms / Pepper Strategies)  
13. Configuration Reference  
14. Security Considerations  
15. Testing & Development Workflow  
16. Roadmap  
17. Contributing  
18. License  

---

## 1. Design Principles

| Principle        | Applied As |
|------------------|------------|
| Explicitness     | No implicit magic; registries & factories are opt‑in, discovery is idempotent |
| Determinism      | Config parsing, benchmarking, pepper application are reproducible and pure |
| Centralization   | Pepper logic lives in one subsystem (no duplicated per‑algorithm code) |
| Isolation        | Global mutable state limited to small registries with snapshot restore for tests |
| Extensibility    | New algorithms / policies / pepper strategies via lightweight decorators |
| Observability    | Warnings for weak params, structured logs, integrity hash on generated configs |
| Fail Fast        | Aggregated configuration validation errors; no partially silent misconfig |
| Testability      | Narrow façades, dependency‑free pure conversions, high coverage |
| Evolvability     | `needs_rehash` + rehash workflow; parameters can be raised in production safely |

---

## 2. High‑Level Architecture

```
securitykit/
  api/                   (Stable public surface; lazy symbol resolution)
  hashing/
    algorithm.py         (Façade: pepper application + guards + error wrapping)
    algorithms/          (Raw implementations: hash_raw / verify_raw / needs_rehash)
    policies/            (Policy dataclasses + BENCH_SCHEMA)
    *registry.py         (Algorithm / policy registries)
    factory.py           (Config → policy + façade)
  transform/pepper/      (Pepper strategies, builder, pipeline)
  password/              (PasswordPolicy + PasswordValidator)
  utils/config_loader/   (Deterministic config → object infrastructure)
  bench/                 (Benchmark enumeration, engine, analyzer, CLI)
  bootstrap.py           (Auto benchmark + integrity-protected env generation)
```

Data / control flow (typical hash operation):

```
password -> PasswordValidator -> Pepper Pipeline (if enabled) -> Algorithm façade
          -> underlying raw implementation (argon2, bcrypt, ...) -> encoded hash
```

---

## 3. Module Map (Public vs. Internal)

| Layer | Public Import | Notes |
|-------|---------------|-------|
| High-level API | `securitykit.api` | Stable; prefer for application code |
| Hash façade | `securitykit.hashing.Algorithm` | Direct use for custom flows |
| Policies | `securitykit.hashing.policies.argon2.Argon2Policy` | Dataclasses (frozen) |
| Password | `securitykit.password.PasswordPolicy / PasswordValidator` | Complexity rules |
| Pepper | `securitykit.transform.pepper` | Normally implicit via façade |
| Benchmark | `python -m securitykit.bench.cli` | Optional tuning |
| Config loader | `securitykit.utils.config_loader` | Internal utility (safe for advanced uses) |
| Bootstrap | `securitykit.bootstrap.ensure_env_config()` | Usually invoked once at startup |

---

## 4. Pepper Subsystem Overview

Config‑driven transformations applied *before* hashing:

| Mode            | Transformation                               | Strength Category |
|-----------------|----------------------------------------------|-------------------|
| `noop`          | identity                                     | – |
| `prefix`        | `prefix + password`                          | Obfuscation |
| `suffix`        | `password + suffix`                          | Obfuscation |
| `prefix_suffix` | Wrap with prefix and suffix                  | Obfuscation |
| `interleave`    | Insert token every N chars                   | Weak obfuscation |
| `hmac`          | `hex(HMAC(key, password))`                   | Cryptographic |

Only `hmac` provides cryptographic strengthening. Modes are mutually exclusive.
Applied exactly once (façade). Exported benchmark configs intentionally exclude pepper keys.

---

## 5. Hashing Subsystem

- Unified façade: `Algorithm(variant: str, policy: Policy, config: Mapping[str,str] | None = None)`
  - Applies pepper (if enabled in config/env)
  - Rejects empty passwords
  - Delegates to raw implementation (`hash_raw`, `verify_raw`, `needs_rehash`)
- Built‑in variants: Argon2 (`variant="argon2"`); bcrypt available / extensible
- Registries:
  - `register_algorithm("argon2")`
  - `register_policy("argon2")`
- Policies can declare `BENCH_SCHEMA` for tuning (cartesian enumeration)
- Rehash logic:
  - Argon2: delegated to `argon2.PasswordHasher.check_needs_rehash`
  - bcrypt: compare cost factor vs. policy value

---

## 6. Password Policies & Validation

`PasswordPolicy` dataclass fields (examples):

| Field | Meaning |
|-------|---------|
| `min_length` | Minimum length |
| `require_upper/lower/digit/special` | Complexity booleans |

Used by `PasswordValidator` before hashing. Violations raise a domain exception (never produce a hash for invalid input).

---

## 7. Configuration Loader

Deterministic pipeline for mapping → typed object:

Parsing heuristics (ordered):
1. Non‑strings unchanged
2. Booleans: `true/false/on/off/yes/no`
3. Sizes: `64k`, `32M`, `1G`, `8kb`, etc. (binary multiples)
4. Int pattern
5. Float pattern
6. Lists: split on `,` or `;`
7. Fallback: stripped string

Primitive type enforcement second pass (int/float/bool) provides clear “Type mismatch” aggregation.

`export_schema(cls, prefix)` produces structured metadata for docs / automation.

---

## 8. Benchmarking & Auto Bootstrap

Benchmark flow:
1. Enumerate combinations from `BENCH_SCHEMA`
2. Time hashing (median/min/max/stddev)
3. Filter candidates near target (± tolerance)
4. Pick balanced (variance of normalized dimension positions) or fallback to closest
5. Output best config + optionally export `.env`

Auto bootstrap (`ensure_env_config()`):
- Loads `.env` then `.env.local`
- Validates integrity hash if present
- Checks required keys for selected variant (`HASH_VARIANT`)
- If incomplete & `AUTO_BENCHMARK=1` & policy has `BENCH_SCHEMA` → run benchmark (pepper neutralized) → write `.env.local` with:
  - Tuned parameters
  - `GENERATED_BY`
  - `GENERATED_SHA256`
- Concurrency safe (file lock if `portalocker`)

Pepper keys are **always excluded** from generated files.

---

## 9. Public API (`securitykit.api`)

Lazy, stable export surface:

| Symbol | Purpose |
|--------|---------|
| `hash_password` / `verify_password` / `rehash_password` | High-level functional interface |
| `Algorithm` | Hash façade (advanced/manual flows) |
| `HashingFactory` | Build façade from config mapping |
| `register_algorithm` / `list_algorithms` / `get_algorithm_class` | Algorithm registry introspection |
| `register_policy` / `list_policies` / `get_policy_class` | Policy registry introspection |
| `Argon2Policy`, `BcryptPolicy` | Built‑in policies |
| `PasswordPolicy`, `PasswordValidator` | Password complexity system |

No legacy `PasswordSecurity` class — replaced by functional API + façade.

---

## 10. Quick Start Examples

### Hash + Verify (Functional)

```python
from securitykit.api import hash_password, verify_password

h = hash_password("StrongExample1!")
assert verify_password("StrongExample1!", h)
```

### Rehash Path

```python
from securitykit.api import verify_password, rehash_password

if verify_password(candidate, stored_hash):
    new_hash = rehash_password(candidate, stored_hash)
    if new_hash != stored_hash:
        persist_new_hash(new_hash)
```

### Manual Façade + Policy

```python
from securitykit.hashing import Algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy

policy = Argon2Policy(time_cost=3, memory_cost=64*1024, parallelism=2)
algo = Algorithm("argon2", policy)  # Pepper controlled by PEPPER_* config/env

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

## 11. Rehash Workflow

When policy parameters change (e.g. raising Argon2 time cost), legacy hashes can be upgraded lazily:

1. User logs in
2. Verify password
3. Call `rehash_password` — if parameters outdated → returns upgraded hash
4. Persist new hash atomically

This amortizes migrations over active user logins.

---

## 12. Extensibility

### New Policy

```python
from dataclasses import dataclass
from securitykit.hashing.policy_registry import register_policy

@register_policy("scrypt")
@dataclass(frozen=True)
class ScryptPolicy:
    ENV_PREFIX: str = "SCRYPT_"
    BENCH_SCHEMA = {"n": [2**14, 2**15], "r": [8, 16], "p": [1, 2]}
    n: int = 2**14
    r: int = 8
    p: int = 1
    def to_dict(self): return {"n": self.n, "r": self.r, "p": self.p}
    def __post_init__(self):
        if self.n < 2**14:
            raise ValueError("n too low")
```

### New Raw Algorithm

```python
from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.scrypt import ScryptPolicy

@register_algorithm("scrypt")
class Scrypt:
    DEFAULT_POLICY_CLS = ScryptPolicy

    def __init__(self, policy: ScryptPolicy | None = None):
        policy = policy or ScryptPolicy()
        self.policy = policy

    def hash_raw(self, peppered_password: str) -> str:
        # perform hashing using library scrypt(...)
        ...

    def verify_raw(self, stored_hash: str, peppered_password: str) -> bool:
        ...

    def needs_rehash(self, stored_hash: str) -> bool:
        ...
```

Façade (`Algorithm`) handles pepper application & empty password guard; you implement only raw methods.

### New Pepper Strategy

```python
from dataclasses import dataclass
from typing import ClassVar
from securitykit.transform.pepper.core import register_strategy

@register_strategy("reverse")
@dataclass(frozen=True)
class ReverseStrategy:
    name: ClassVar[str] = "reverse"
    def apply(self, password: str) -> str:
        return password[::-1]
```

Use with `PEPPER_MODE=reverse`.

---

## 13. Configuration Reference

Core hashing:

```
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
```

Password policy:

```
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
```

Pepper:

```
PEPPER_ENABLED=true
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=<secret>
PEPPER_HMAC_ALGO=sha256
# (Alternative modes: prefix, suffix, prefix_suffix, interleave + related keys)
```

Bootstrap / Benchmark:

```
AUTO_BENCHMARK=0
AUTO_BENCHMARK_TARGET_MS=250
SECURITYKIT_DISABLE_BOOTSTRAP=0
```

Generated metadata (bootstrap adds):

```
GENERATED_BY=securitykit-bench vX.Y.Z
GENERATED_SHA256=<integrity-hash>
```

---

## 14. Security Considerations

| Aspect | Treatment | Notes |
|--------|-----------|-------|
| Pepper | Central strategy; only HMAC cryptographically strong | Non-HMAC modes are structured obfuscation |
| Hash Parameters | Policies validated; warnings for low settings | Raise values over time + rehash |
| Rehash Safety | Conditional rehash after successful verify | Avoids forced migrations |
| Integrity of Generated Config | SHA256 over key=value pairs | Warn on tampering |
| Configuration Validation | Aggregated errors, typed enforcement | Prevent partial misconfig states |
| Empty Passwords | Rejected by façade early | No silent hashing of empty inputs |
| Logging | Parameter warnings & fallback events | Monitor for unexpected `noop` pepper |

---

## 15. Testing & Development Workflow

Run everything:

```bash
make test
```

Typical loops:

```bash
pytest -k hashing -q
pytest tests_new/bench/test_bench_components.py -q
pytest --cov=src --cov-report=term-missing
```

Benchmark tests stub timing (no slow runs). Real benchmarking is an *opt‑in* manual or CI stage.

---

## 16. Roadmap

| Item | Status | Notes |
|------|--------|-------|
| Scrypt implementation | Planned | Memory-hard alternative |
| Pepper rotation (`PEPPER_VERSION`) | Planned | Dual verification window |
| Multi-hash migration helper | Planned | Legacy → Argon2/Bcrypt upgrade |
| JSON / machine-readable benchmark export | Planned | Automation & dashboards |
| Observability hooks (metrics) | Planned | Hash counts, rehash events |
| Async façade | Investigating | ASGI / non-blocking integration |
| Layered config sources (env + file + remote) | Planned | Declarative precedence |
| Hardware advisory heuristics | Planned | Param recommendations based on host |
| Per-user derived pepper (HKDF) | Planned | Narrow compromise blast radius |

---

## 17. Contributing

1. Create a feature or fix branch: `feat/<topic>` or `fix/<issue>`
2. Implement with tests (maintain / improve coverage)
3. Document new public symbols (README or subsystem README)
4. Ensure no new lint violations / type regressions
5. Submit PR with rationale, benchmarks (if param changes), and migration notes

---

## 18. License

MIT – see [LICENSE](./LICENSE).

---

### Minimal Reference Table

| Task | Import / Command |
|------|------------------|
| Hash password | `from securitykit.api import hash_password` |
| Verify password | `from securitykit.api import verify_password` |
| Conditional rehash | `from securitykit.api import rehash_password` |
| Manual façade | `from securitykit.hashing import Algorithm` |
| Policy class | `from securitykit.hashing.policies.argon2 import Argon2Policy` |
| Password complexity | `from securitykit.password import PasswordPolicy, PasswordValidator` |
| Benchmark CLI | `python -m securitykit.bench.cli ...` |
| Bootstrap (manual) | `from securitykit.bootstrap import ensure_env_config` |
| Config loader (advanced) | `from securitykit.utils.config_loader import ConfigLoader` |

---

**Questions / Ideas?**  
Open an issue or draft a PR with: environment constraints, target latency, variant(s), and pepper mode for tailored guidance.
