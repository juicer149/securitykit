# SecurityKit Hashing

> Modern, extensible, test‑friendly password hashing with validated policies,
> pluggable algorithms, benchmarking support, and configuration‑driven construction.

Highlights:
- Minimal core package; algorithms are opt‑in via extras (conditional registration).
- Frozen policy dataclasses with validation (no runtime inheritance).
- Registries store raw classes (type), case‑insensitive variant keys.
- Central pepper subsystem (strategy + config; no per‑algo pepper args).
- Algorithm façade applies pepper, wraps errors, and centralizes cross‑variant tolerance.
- Rehash semantics per algorithm; optional benchmarking schemas for tuning.
- Login‑time migration helper for seamless algorithm/policy upgrades.

---

## Contents

1. Goals & Non‑Goals  
2. Installation  
3. Architecture Overview  
4. Core Concepts  
5. Public Modules  
6. Quick Start  
7. Configuration & Environment Keys  
8. Rehash Semantics  
9. Pepper Subsystem  
10. Benchmark Interoperability  
11. Extending (Policies & Algorithms)  
12. Error & Exception Model  
13. Testing Strategy & Patterns  
14. Best Practices & Security Notes  
15. Migration / “What Changed”  
16. Roadmap  
17. Appendix: Minimal Manual Flow  

---

## 1. Goals & Non‑Goals

| Goal | Description |
|------|-------------|
| Uniform Interface | One façade (`Algorithm`) exposing `hash`, `verify`, `needs_rehash` |
| Explicit Configuration | Deterministic construction from env or mapping |
| Safety | Policy dataclasses validate bounds in `__post_init__` |
| Extensibility | New algorithms / policies via decorators and discovery |
| Benchmark Ready | Optional `BENCH_SCHEMA` enumerates tuning space |
| Structural Typing | Avoid inheritance complexity and fragile generics |
| Testability | Registry‑driven dynamic parametrization |
| Runtime Clarity | Registries store raw `type` only |
| Central Pepper | One subsystem; zero duplication in implementations |
| Minimal Core | Algorithms are optional extras with conditional registration |

Non‑Goals:
- Universal hash decoder beyond what’s needed for needs_rehash and variant detection
- Forcing environment as the only configuration source
- Hiding algorithm parameters
- Per‑algorithm pepper behavior

---

## 2. Installation

- Python: >= 3.10

Minimal core (no crypto libs by default):
```bash
pip install securitykit
```

Opt‑in algorithms via extras:
- Argon2: `pip install "securitykit[alg_argon2]"`
- bcrypt: `pip install "securitykit[alg_bcrypt]"`
- Werkzeug PBKDF2: `pip install "securitykit[alg_werkzeug]"`

Development (runs full test suite with all extras):
```bash
pip install -e ".[dev]"
```

Notes:
- Algorithms register conditionally at import time based on what’s installed.
- In CI, install dev extra to run all algorithm tests.

---

## 3. Architecture Overview

```
  +----------------------+
  |  Config (env/dict)   |
  +----------+-----------+
             |
             v
      +----------------+       +--------------------+
      | HashingFactory | ----> | Policy (dataclass) |
      +------+---------+       +--------------------+
             |
             v
       +------------+
       | Algorithm  |  (façade: pepper + guards + errors + cross-variant tolerance)
       +------+-----+
              |
              v
      +-----------------------+
      | Implementation        |
      | hash_raw/verify_raw   |
      +-----------------------+
              |
              v
  Underlying libs (argon2-cffi, bcrypt, werkzeug.security, hashlib.scrypt)
```

Discovery:
- `load_all()` imports `hashing/policies/*` and `hashing/algorithms/*` exactly once
- Registrations happen via decorators
- Snapshots allow restore in tests/reloads

Conditional registration:
- Algorithm modules register only if their third‑party dependency is importable.
- Registry contents reflect what’s installed (e.g., `werkzeug_pbkdf2` is absent if Werkzeug isn’t installed).

---

## 4. Core Concepts

| Concept | Description |
|---------|-------------|
| Policy | Frozen dataclass with parameters, validation, optional `BENCH_SCHEMA` |
| Algorithm Implementation | Class exposing `hash_raw`, `verify_raw`, `needs_rehash` |
| Algorithm Façade | Applies pepper, handles empty password, wraps errors, centralizes cross‑variant tolerance |
| Pepper Subsystem | Strategy registry + pipeline; configured via `PEPPER_*` |
| Registry | Case‑insensitive variant → class mapping (`type`) |
| BENCH_SCHEMA | Enumerates parameter search grid for benchmarking |
| Variant Detection | Best‑effort detection via `utils.detect_variant(stored_hash)` |
| Login‑time Migration | Minimal helper `authenticate_and_upgrade(password, stored_hash, config)` |

---

## 5. Public Modules

| Module | Purpose |
|--------|---------|
| `hashing/algorithm.py` | Façade (pepper + delegation + error wrapping + cross‑variant tolerance) |
| `hashing/algorithms/argon2.py` | Argon2id implementation (argon2‑cffi) |
| `hashing/algorithms/bcrypt.py` | bcrypt implementation |
| `hashing/algorithms/scrypt.py` | scrypt implementation (hashlib.scrypt) |
| `hashing/algorithms/wz_pbkdf2.py` | Werkzeug PBKDF2 implementation |
| `hashing/policies/*` | Policy dataclasses + tuning schemas |
| `hashing/factory.py` | Config → policy + façade |
| `hashing/algorithm_registry.py` | Algorithm registry |
| `hashing/policy_registry.py` | Policy registry |
| `hashing/registry.py` | Discovery (`load_all`) |
| `hashing/utils.py` | `detect_variant`, helpers |
| `api/migration.py` | `authenticate_and_upgrade` (login‑time migration) |
| `transform/pepper/*` | Pepper strategies/pipeline |
| `utils/config_loader/*` | Deterministic config → objects |
| `bench/*` | Optional benchmarking subsystem |
| `password/*` | Password policy + validator |

---

## 6. Quick Start

Programmatic configuration:
```python
from securitykit.hashing import Algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy

policy = Argon2Policy(time_cost=3, memory_cost=64*1024, parallelism=2)
algo = Algorithm("argon2", policy=policy)

digest = algo.hash("CorrectHorseBatteryStaple!")
assert algo.verify(digest, "CorrectHorseBatteryStaple!")

if algo.needs_rehash(digest):
    digest = algo.hash("CorrectHorseBatteryStaple!")
```

Factory + pepper:
```python
import os
from securitykit.hashing.factory import HashingFactory

config = {
    "HASH_VARIANT": "bcrypt",
    "BCRYPT_ROUNDS": 12,
    "PEPPER_MODE": "hmac",
    "PEPPER_HMAC_KEY": "ProductionRandom32+ByteKey",
}

algo = HashingFactory(config).get_algorithm()
h = algo.hash("UserPass123!")
assert algo.verify(h, "UserPass123!")
```

Login‑time migration/upgrade:
```python
from securitykit.api.migration import authenticate_and_upgrade

dest_cfg = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": 3,
    "ARGON2_MEMORY_COST": 131072,
    "ARGON2_PARALLELISM": 2,
}

ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
if ok and new_hash is not None:
    persist(new_hash)  # store upgraded hash
```

---

## 7. Configuration & Environment Keys

Convention: `{VARIANT}_{PARAM}` uppercased (e.g., `ARGON2_TIME_COST`).

Common:
- `HASH_VARIANT`: `argon2` | `bcrypt` | `scrypt` | `werkzeug_pbkdf2`

Argon2 (argon2‑cffi):
```
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
```

bcrypt:
```
BCRYPT_ROUNDS=12
```

scrypt (hashlib):
```
SCRYPT_N=16384           # power of two
SCRYPT_R=8
SCRYPT_P=1
SCRYPT_SALT_LENGTH=16
SCRYPT_HASH_LENGTH=32
# OpenSSL memory cap (bytes); default 512 MiB if unset:
SCRYPT_MAXMEM=536870912
```

Werkzeug PBKDF2:
```
WERKZEUG_PBKDF2_METHOD=pbkdf2:sha256
WERKZEUG_PBKDF2_ITERATIONS=260000
WERKZEUG_PBKDF2_SALT_LENGTH=16
```

Pepper (see section 9):
```
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=SuperStrongPepperKey!!!
# optional: PEPPER_HMAC_ALGO=sha512
```

Behavior:
- Missing optional keys → policy defaults (warning logged).
- Invalid values → immediate exception from policy constructors or config loader.
- Provide a mapping (dict) to `HashingFactory` for explicit runtime configuration (recommended for apps).

---

## 8. Rehash Semantics

| Algorithm | Mechanism |
|-----------|-----------|
| Argon2 | `argon2.PasswordHasher.check_needs_rehash(stored_hash)` |
| bcrypt | Parse cost factor from `$2b$CC$...` and compare vs policy rounds |
| scrypt | Decode `$scrypt$...` params; compare logN/r/p and hash length vs policy |
| Werkzeug PBKDF2 | Parse `pbkdf2:sha256:ITERATIONS$...`; compare iterations vs policy |

Notes:
- Malformed hashes: `needs_rehash` returns `False` (conservative) and logs when appropriate.
- Pepper changes alone do not trigger `needs_rehash`; treat pepper rotation as a deliberate migration step (see section 15 and login‑time migration).

---

## 9. Pepper Subsystem

Properties:
- Centralized (façade applies once before hashing/verification).
- Strategy‑based: `noop`, `prefix`, `suffix`, `prefix_suffix`, `interleave`, `hmac`.
- Configured exclusively via `PEPPER_*` keys.

Keys:

| Key | Default | Description |
|-----|---------|-------------|
| `PEPPER_ENABLED` | `true` | Master switch |
| `PEPPER_MODE` | `noop` | Strategy |
| `PEPPER_SECRET` | (empty) | Base secret for simple modes |
| `PEPPER_PREFIX` / `PEPPER_SUFFIX` | (empty) | Overrides for prefix/suffix |
| `PEPPER_INTERLEAVE_FREQ` | `0` | Insert token every N chars (≤0 noop) |
| `PEPPER_INTERLEAVE_TOKEN` | (empty) | Token for interleave |
| `PEPPER_HMAC_KEY` | (empty) | Required for `hmac` |
| `PEPPER_HMAC_ALGO` | `sha256` | HMAC hash function |

Only `hmac` provides cryptographic strengthening; others are structured concatenations.

---

## 10. Benchmark Interoperability

Policies can define a `BENCH_SCHEMA`, e.g.:

```python
BENCH_SCHEMA = {
    "time_cost": [2, 3, 4],
    "memory_cost": [65536, 131072],
    "parallelism": [1, 2],
}
```

Process:
- Enumerate candidates → run timing → score → select → emit config.
- CI: reduce candidate lists for speed.

---

## 11. Extending (Policies & Algorithms)

Policy skeleton:
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
    def __post_init__(self):
        # validate ranges, powers of two, warn on low settings, etc.
        ...
```

Algorithm skeleton (conditional registration):
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
        def __init__(self, policy: MyAlgoPolicy | None = None):
            policy = policy or MyAlgoPolicy()
            if not isinstance(policy, MyAlgoPolicy):
                raise TypeError("policy must be MyAlgoPolicy")
            self.policy = policy
        def hash_raw(self, peppered_password: str) -> str: ...
        def verify_raw(self, stored_hash: str, peppered_password: str) -> bool: ...
        def needs_rehash(self, stored_hash: str) -> bool: ...
```

The façade (Algorithm) handles pepper, empty password guard, cross‑variant tolerance, and error wrapping.

---

## 12. Error & Exception Model

| Exception | Source | Meaning |
|-----------|--------|---------|
| `HashingError` | Façade/delegate | Hash input invalid / delegate failure |
| `VerificationError` | Façade/delegate | Unexpected verify failure (not just mismatch) |
| `InvalidPolicyConfig` / `ValueError` | Policy init | Invalid parameter |
| `UnknownAlgorithmError` | Registry | Unknown variant (might be missing extra) |
| `UnknownPolicyError` | Registry | Unknown policy |
| `ConfigValidationError` | Config loader | Conversion/type errors |
| `PepperConfigError` | Pepper builder | Missing required secret/key |
| `PepperStrategyConstructionError` | Strategy build | Unsupported mode/params |

Mismatches return `False`. Cross‑variant verification errors (e.g., trying to verify an Argon2 hash with bcrypt) are handled centrally by the façade:
- It detects a foreign variant via `utils.detect_variant`.
- Returns `False` instead of surfacing an exception from the underlying library.
- Same‑variant malformed hashes still surface as `VerificationError` (diagnostic).

---

## 13. Testing Strategy & Patterns

| Test Type | Target |
|-----------|--------|
| Roundtrip | `hash` / `verify` including mismatch |
| Pepper | Hash diff & cross verify failure |
| Param Encoding | Parse Argon2 / bcrypt / scrypt / Werkzeug parameters from hashes |
| Rehash | Old policy → stronger policy for all supported variants |
| Cross‑Variant Verify | Wrong variant returns False (no exceptions) |
| Migration | Login‑time authenticate+upgrade across all pairs |
| Error Paths | Empty password, delegate exceptions, malformed encodings |
| Config Loader | Conversions + type mismatches |
| Bench Smoke | Non‑empty schema enumeration; bounded candidates |

Tests parameterize over the registry; variants not installed (extras missing) are skipped automatically.

---

## 14. Best Practices & Security Notes

| Practice | Reason |
|----------|--------|
| Frozen policies | Prevent silent runtime downgrades |
| Central pepper | Consistency & reduced errors |
| Prefer HMAC pepper | Cryptographic binding to input |
| Lazy rehash on login | Zero downtime policy/variant upgrades |
| Rotate pepper keys | Control blast radius and migration |
| Isolate pepper key | Keep separate from DB backups |
| Log warnings | Visibility on weak/legacy settings |
| Pin crypto versions | Avoid semantic shifts across upgrades |

---

## 15. Migration / “What Changed”

| Old | New |
|-----|-----|
| Algorithms in core deps | Minimal core; algorithms as optional extras |
| Eager registrations | Conditional registration based on installed extras |
| Per‑algo pepper | Central pepper pipeline (`PEPPER_*`) |
| Implementation `hash()` | `hash_raw`; façade applies pepper and guards |
| Cross‑variant raises | Central tolerance: foreign variant → `False` |
| No login migration | `authenticate_and_upgrade(password, stored_hash, config)` helper |
| No variant detection | `utils.detect_variant(stored_hash)` |
| scrypt memory errors | `SCRYPT_MAXMEM` default (512 MiB), tunable via env |
| PBKDF2 env keys unclear | `WERKZEUG_PBKDF2_*` config documented |

---

## 16. Roadmap

| Item | Status | Notes |
|------|--------|-------|
| scrypt implementation | Shipped | Resource‑friendly defaults; `SCRYPT_MAXMEM` control |
| Werkzeug PBKDF2 | Shipped | Optional extra; iterations parsed for rehash |
| Login‑time migration helper | Shipped | `authenticate_and_upgrade` |
| Pepper rotation tooling | Planned | Versioned keys / dual verify |
| Weighted benchmark scoring | Planned | Heuristic tuning |
| Advisory heuristics | Planned | Hardware‑aware guidance |
| Hash format compatibility | Investigating | Legacy variants/encodings |
| Per‑user HKDF pepper | Planned | Blast radius reduction |

---

## 17. Appendix: Minimal Manual Flow

```python
from securitykit.hashing.factory import HashingFactory

config = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": f"{64*1024}",
    "ARGON2_PARALLELISM": "2",
    # optional pepper
    "PEPPER_MODE": "hmac",
    "PEPPER_HMAC_KEY": "ProductionRandom32+ByteKey",
}

algo = HashingFactory(config).get_algorithm()

stored = algo.hash("UserPass123!")
assert algo.verify(stored, "UserPass123!")
if algo.needs_rehash(stored):
    stored = algo.hash("UserPass123!")
```

Login‑time migration example:
```python
from securitykit.api.migration import authenticate_and_upgrade

dest_cfg = {"HASH_VARIANT": "argon2", "ARGON2_TIME_COST": 3, "ARGON2_MEMORY_COST": 131072, "ARGON2_PARALLELISM": 2}
ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
if ok and new_hash is not None:
    persist(new_hash)
```

---

Questions?
- Please open an issue and include:
  - Variants in use and installed extras
  - Current policy values and target latency window
  - Hardware/memory constraints (note `SCRYPT_MAXMEM`)
  - Pepper mode and rotation plan
  - Any migration goals (e.g., bcrypt → Argon2)
