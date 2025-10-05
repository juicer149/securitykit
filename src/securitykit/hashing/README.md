# SecurityKit Hashing

Modern, extensible, diagnostics‑aware password hashing with validated policies, pluggable algorithms, centralized pepper, and configuration‑driven construction.

Highlights
- Minimal core; algorithms are opt‑in via extras (conditional registration).
- Frozen-style policies with validation and optional benchmark schemas.
- Diagnostics snapshot exposes availability, versions, and capabilities (e.g., supports_secret).
- Central pepper subsystem; no per‑algorithm pepper code.
- Algorithm façade applies pepper once, adds guards, error wrapping, and cross‑variant tolerance.
- Rehash semantics per algorithm; login‑time migration helper for upgrades.
- Test‑friendly design: discovery, registries, and config loaders.

---

## Contents

1. Goals & Non‑Goals
2. Installation
3. Architecture Overview
4. Discovery & Diagnostics
5. Core Concepts
6. Public Modules
7. Quick Start
8. Configuration & Environment Keys
9. Rehash Semantics
10. Pepper Subsystem (How It Integrates)
11. Benchmark Interoperability
12. Extending (Policies & Algorithms)
13. Error & Exception Model
14. Testing Strategy & Patterns
15. Best Practices & Security Notes
16. Migration / “What Changed”
17. Roadmap
18. Appendix: Minimal Manual Flow

---

## 1. Goals & Non‑Goals

| Goal | Description |
|------|-------------|
| Uniform Interface | One façade (`Algorithm`) exposing `hash`, `verify`, `needs_rehash`. |
| Explicit Configuration | Deterministic construction from env or mapping. |
| Safety | Policy dataclasses validate bounds and emit warnings. |
| Extensibility | New algorithms/policies via decorators and discovery. |
| Diagnostics‑Aware | Capability probes drive behavior (e.g., native pepper vs HMAC). |
| Central Pepper | Strategy‑based, variant‑agnostic pepper handling. |
| Benchmark Ready | Optional `BENCH_SCHEMA` enumerates tuning space. |
| Testability | Registry‑driven, late‑bound diagnostics, config loader. |
| Minimal Core | Algorithms are optional extras with conditional registration. |

Non‑Goals
- Universal hash decoder beyond variant detection and parameter checks for rehash.
- Enforcing environment as the only config source (mappings are supported).
- Hiding algorithm parameters (policies are explicit).
- Per‑algorithm pepper paths (centralized instead).

---

## 2. Installation

- Python: >= 3.10

Core (no crypto libs by default):
```bash
pip install securitykit
```

Opt‑in algorithms via extras:
- Argon2: `pip install "securitykit[alg_argon2]"`
- bcrypt: `pip install "securitykit[alg_bcrypt]"`
- Werkzeug PBKDF2: `pip install "securitykit[alg_werkzeug]"`

Development (run full suite):
```bash
pip install -e ".[dev]"
```

Notes
- Algorithms register conditionally at import time based on what’s installed.
- CI: install the dev extra to test all variants.

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
       | Algorithm  |  (façade: pepper + guards + diagnostics + errors + cross-variant tolerance)
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

Key points
- The façade constructs a diagnostics‑aware pepper plan and delegates to the concrete implementation.
- Implementations are thin: `hash_raw`, `verify_raw`, `needs_rehash`.
- Policies capture cost parameters and read diagnostics as needed.

---

## 4. Discovery & Diagnostics

Discovery
- `load_all()` imports `hashing/policies/*` and `hashing/algorithms/*` exactly once.
- Registration happens via decorators; registries hold raw classes by case‑insensitive variant keys.
- Snapshots allow restore in tests/reloads.

Diagnostics snapshot (capabilities)
- Centralized in `hashing/diagnostics.py` and cached by `hashing/registry.load_all()`.
- Each algorithm provides a small probe returning `CapabilityInfo`:
  - `available`: bool
  - `version`: str
  - `extra`: dict of capabilities (e.g., `{"supports_secret": True}` for Argon2 keyed mode).
- Policies (e.g., Argon2) can read their diagnostic entry to expose `version` and booleans such as `supports_internal_pepper`.

Pepper integration uses late‑bound diagnostics:
- `PepperFactory` imports `securitykit.hashing.registry` at runtime and calls `get_diagnostic(variant)` to decide native secret vs HMAC prehash.

---

## 5. Core Concepts

| Concept | Description |
|--------|-------------|
| Policy | Dataclass with parameters, validation, and optional `BENCH_SCHEMA`. |
| CapabilityInfo | Diagnostics for a variant: `available`, `version`, `extra` capabilities. |
| Algorithm Implementation | The minimal core for a variant: `hash_raw`, `verify_raw`, `needs_rehash`. |
| Algorithm Façade | Resolves implementation, builds pepper plan, applies guards, wraps errors, tolerates cross‑variant. |
| Pepper Subsystem | Strategy registry + builder + factory. The façade applies pepper exactly once. |
| Registry | Case‑insensitive name → class mapping (`type`), populated on discovery. |
| Variant Detection | Best‑effort via `hashing.utils.detect_variant(stored_hash)`. |
| Migration Helper | `authenticate_and_upgrade(password, stored_hash, config)` for login‑time upgrades. |

---

## 6. Public Modules

| Module | Purpose |
|--------|---------|
| `hashing/algorithm.py` | Façade: pepper + delegation + error wrapping + cross‑variant tolerance. |
| `hashing/algorithms/argon2.py` | Argon2id implementation (argon2‑cffi), supports native secret when available. |
| `hashing/algorithms/bcrypt.py` | bcrypt implementation. |
| `hashing/algorithms/scrypt.py` | scrypt (hashlib.scrypt) with custom encoding. |
| `hashing/algorithms/wz_pbkdf2.py` | Werkzeug PBKDF2 implementation. |
| `hashing/policies/*` | Policy dataclasses + tuning schemas; some read diagnostics. |
| `hashing/factory.py` | Config → policy + façade; forwards mapping to the façade (pepper access). |
| `hashing/algorithm_registry.py` | Algorithm registry. |
| `hashing/policy_registry.py` | Policy registry. |
| `hashing/diagnostics.py` | CapabilityInfo probes (centralized). |
| `hashing/registry.py` | Discovery (`load_all`) + cached diagnostics snapshot + `get_diagnostic`. |
| `hashing/utils.py` | `detect_variant`, helpers. |
| `api/migration.py` | `authenticate_and_upgrade` (login‑time migration). |
| `transform/pepper/*` | Pepper strategies, builder, pipeline, and diagnostics‑aware factory. |
| `utils/config_loader/*` | Deterministic config → objects. |
| `bench/*` | Optional benchmarking subsystem. |
| `password/*` | Password policy + validator + gate (validated before hashing at API level). |

---

## 7. Quick Start

Programmatic configuration
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

Factory + pepper
```python
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

Login‑time migration/upgrade
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

## 8. Configuration & Environment Keys

Convention: `{VARIANT}_{PARAM}` uppercased (e.g., `ARGON2_TIME_COST`).

Common
- `HASH_VARIANT`: `argon2` | `bcrypt` | `scrypt` | `werkzeug_pbkdf2`

Argon2 (argon2‑cffi)
```
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
```

bcrypt
```
BCRYPT_ROUNDS=12
```

scrypt (hashlib)
```
SCRYPT_N=16384           # power of two
SCRYPT_R=8
SCRYPT_P=1
SCRYPT_SALT_LENGTH=16
SCRYPT_HASH_LENGTH=32
# OpenSSL memory cap (bytes); default 512 MiB if unset:
SCRYPT_MAXMEM=536870912
```

Werkzeug PBKDF2
```
WERKZEUG_PBKDF2_METHOD=pbkdf2:sha256
WERKZEUG_PBKDF2_ITERATIONS=260000
WERKZEUG_PBKDF2_SALT_LENGTH=16
```

Pepper (section 10)
```
PEPPER_ENABLED=true
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=SuperStrongPepperKey!!!
# optional: PEPPER_HMAC_ALGO=sha512
```

Behavior
- Missing optional keys → policy defaults (warning logged).
- Invalid values → exceptions from policy constructors or the config loader.
- Prefer passing a mapping (dict) to `HashingFactory` for explicit runtime configuration.

---

## 9. Rehash Semantics

| Algorithm | Mechanism |
|----------|-----------|
| Argon2 | `argon2.PasswordHasher.check_needs_rehash(stored_hash)` |
| bcrypt | Parse cost factor from `$2b$CC$...`; compare vs policy rounds. |
| scrypt | Decode `$scrypt$...` params; compare logN/r/p and hash length vs policy. |
| Werkzeug PBKDF2 | Parse `pbkdf2:sha256:ITERATIONS$...`; compare iterations vs policy. |

Notes
- Malformed hashes: `needs_rehash` returns `False` (conservative) and logs when appropriate.
- Pepper changes alone do not trigger `needs_rehash`; treat pepper rotation as a deliberate migration step (see migration helper).

---

## 10. Pepper Subsystem (How It Integrates)

Properties
- Centralized and variant‑agnostic; the façade applies pepper exactly once.
- Strategy modes: `noop`, `prefix`, `suffix`, `prefix_suffix`, `interleave`, `hmac`.
- Configured via `PEPPER_*` keys.

Diagnostics‑aware HMAC behavior
- If `get_diagnostic(variant).extra['supports_secret']` is True (e.g., Argon2 with native keyed mode), `PepperFactory` passes the key as `algo_kwargs={'secret': <bytes>}` and does not prehash.
- Otherwise, `PepperFactory` builds an external HMAC prehash pipeline.
- Other non‑HMAC modes are built as prehash pipelines regardless of variant.

See the dedicated [Pepper README](../transform/pepper/README.md) for details and security guidance.

---

## 11. Benchmark Interoperability

Policies can define a `BENCH_SCHEMA`, e.g.:
```python
BENCH_SCHEMA = {
    "time_cost": [2, 3, 4],
    "memory_cost": [65536, 131072],
    "parallelism": [1, 2],
}
```

Process
- Enumerate candidates → time → score → select → emit config.
- CI: reduce candidates for speed.

---

## 12. Extending (Policies & Algorithms)

Policy skeleton
```python
from dataclasses import dataclass, asdict
from securitykit.hashing.policy_registry import register_policy
from securitykit.exceptions import InvalidPolicyConfig

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
        if self.n & (self.n - 1) != 0:
            raise InvalidPolicyConfig("n must be a power of two")
```

Algorithm skeleton (conditional registration)
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

The façade handles pepper, empty password guard, cross‑variant tolerance, and error wrapping.

---

## 13. Error & Exception Model

| Exception | Source | Meaning |
|-----------|--------|---------|
| `HashingError` | Façade/delegate | Hashing failure or invalid input. |
| `VerificationError` | Façade/delegate | Unexpected verify failure (not a plain mismatch). |
| `InvalidPolicyConfig` | Policy init | Invalid parameter or constraint. |
| `UnknownAlgorithmError` | Registry | Unknown variant (missing extra). |
| `UnknownPolicyError` | Registry | Unknown policy. |
| `ConfigValidationError` | Config loader | Conversion/type errors. |
| `PepperConfigError` | Pepper builder | Missing required secret/key in `hmac` mode. |
| `PepperStrategyConstructionError` | Strategy build | Unsupported mode/params. |

Mismatches
- Return `False`.
- Cross‑variant attempts are detected via `utils.detect_variant` and coerced to `False` (no exception).
- Same‑variant malformed hashes surface as `VerificationError` for diagnostics.

---

## 14. Testing Strategy & Patterns

| Test Type | Target |
|-----------|--------|
| Roundtrip | `hash` / `verify` including mismatch. |
| Pepper | Hash differences + cross‑verify failure across keys/modes. |
| Param Encoding | Parse Argon2/bcrypt/scrypt/Werkzeug params from hashes. |
| Rehash | Old policy → stronger policy for installed variants. |
| Cross‑Variant Verify | Wrong variant returns `False` (no exception). |
| Migration | `authenticate_and_upgrade` across variant pairs. |
| Error Paths | Empty password, delegate exceptions, malformed encodings. |
| Config Loader | Conversions + type mismatches. |
| Bench Smoke | Non‑empty schema enumeration; bounded candidates. |

Variants not installed are skipped automatically.

---

## 15. Best Practices & Security Notes

| Practice | Reason |
|----------|--------|
| Immutable (frozen) policies | Prevent silent runtime downgrades. |
| Central pepper | Consistency and reduced implementation bugs. |
| Prefer HMAC pepper | Cryptographic binding to input. |
| Lazy rehash on login | Zero‑downtime policy/variant upgrades. |
| Rotate pepper keys | Control blast radius; plan migration windows. |
| Isolate pepper key | Keep separate from DB backups/exports. |
| Log warnings | Visibility on weak/legacy settings. |
| Pin crypto versions | Avoid semantic shifts across upgrades. |

---

## 16. Migration / “What Changed”

| Old | New |
|-----|-----|
| Algorithms in core deps | Minimal core; algorithms as opt‑in extras. |
| Eager registrations | Conditional on installed extras. |
| Per‑algo pepper | Central pepper pipeline (`PEPPER_*`). |
| Implementation `hash()` | `hash_raw`; façade applies pepper and guards. |
| Cross‑variant raises | Central tolerance: foreign variant → `False`. |
| No login migration | `authenticate_and_upgrade(...)` helper. |
| No variant diagnostics | Capability snapshot with `supports_secret`, `version`, etc. |
| scrypt memory errors | `SCRYPT_MAXMEM` default (512 MiB), configurable. |
| Unclear PBKDF2 keys | `WERKZEUG_PBKDF2_*` documented and enforced. |

---

## 17. Roadmap

| Item | Status | Notes |
|------|--------|-------|
| scrypt implementation | Shipped | Resource‑friendly defaults; `SCRYPT_MAXMEM` control. |
| Werkzeug PBKDF2 | Shipped | Optional extra; iterations parsed for rehash. |
| Login‑time migration helper | Shipped | `authenticate_and_upgrade`. |
| Diagnostics deepening | Planned | Additional capability flags per variant. |
| Pepper rotation tooling | Planned | Versioned keys / dual verify. |
| Weighted benchmark scoring | Planned | Heuristic tuning. |
| Advisory heuristics | Planned | Hardware‑aware guidance. |
| Hash format compatibility | Investigating | Legacy encodings. |
| Per‑user HKDF pepper | Planned | Blast radius reduction. |

---

## 18. Appendix: Minimal Manual Flow

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

Questions?
- Open an issue and include:
  - Variants in use and installed extras
  - Policy values and target latency window
  - Hardware/memory constraints (note `SCRYPT_MAXMEM`)
  - Pepper mode and rotation plan
  - Migration goals (e.g., bcrypt → Argon2)
