# SecurityKit Hashing

> Modern, extensible, test‑friendly password hashing layer with strongly
> validated policies, pluggable algorithms, benchmarking support, and
> configuration‑driven construction.

This document describes the current architecture:

- Concrete policy dataclasses (no runtime inheritance hierarchies)
- Simplified registries storing raw classes (`type`)
- Structural typing only (no fragile generics)
- Centralized pepper subsystem (strategy + config driven; no `pepper=` arg)
- Algorithm façade applies pepper + delegates to `hash_raw` / `verify_raw`
- Dynamic test parametrization (registry‑driven, not module‑decorator duplication)
- Separation of algorithm logic from configuration/bootstrap code

---

## Contents

1. Goals & Non‑Goals  
2. Architecture Overview  
3. Core Concepts  
4. Public Modules  
5. Quick Start  
6. Configuration & Environment Keys  
7. Rehash Semantics  
8. Pepper Subsystem  
9. Benchmark Interoperability  
10. Extending (Policies & Algorithms)  
11. Error & Exception Model  
12. Testing Strategy & Patterns  
13. Best Practices & Security Notes  
14. Migration / “What Changed”  
15. Roadmap  
16. Appendix: Minimal Manual Flow  

---

## 1. Goals & Non‑Goals

| Goal | Description |
|------|-------------|
| Uniform Interface | One façade (`Algorithm`) exposing `hash`, `verify`, `needs_rehash` |
| Explicit Configuration | Deterministic construction via env/mapping |
| Safety | Policy dataclasses validate bounds in `__post_init__` |
| Extensibility | New algorithms / policies via decorators |
| Benchmark Ready | Optional `BENCH_SCHEMA` enumerates tuning space |
| Structural Typing | Avoid inheritance complexity |
| Testability | Dynamic registry‑driven parametrization |
| Runtime Clarity | Registries store `type` only |
| Centralized Pepper | Single subsystem; zero duplication in implementations |

**Non‑Goals**

- A universal hash decoder (only what's needed for rehash decisions)
- Forcing environment as the only config source
- Hiding underlying algorithm parameters
- Re‑introducing per‑algorithm pepper behavior

---

## 2. Architecture Overview

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
       | Algorithm  |  (façade: pepper + guards + errors)
       +------+-----+
              |
              v
      +-----------------------+
      | Implementation        |
      | hash_raw/verify_raw   |
      +-----------------------+
              |
              v
  Underlying libs (argon2, bcrypt)
```

Discovery:
- `load_all()` imports `hashing/policies/*` and `hashing/algorithms/*` exactly once (idempotent)
- Registrations occur via decorators
- Snapshots allow `restore_from_snapshots()` in tests/reloads

---

## 3. Core Concepts

| Concept | Description |
|---------|-------------|
| Policy | Frozen dataclass with parameters, validation, optional `BENCH_SCHEMA` |
| Algorithm Implementation | Class exposing `hash_raw`, `verify_raw`, `needs_rehash` |
| Algorithm Façade | Applies pepper and wraps errors |
| Pepper Subsystem | Strategy registry + pipeline |
| Registry | Case‑insensitive variant → class mapping |
| BENCH_SCHEMA | Enumerates parameter search grid |
| Structural Policy Protocol | Minimal shape expectations (`to_dict`, prefix, schema) |

---

## 4. Public Modules

| Module | Purpose |
|--------|---------|
| `hashing/algorithm.py` | Façade (pepper + delegation + error wrapping) |
| `hashing/algorithms/argon2.py` | Argon2id implementation |
| `hashing/algorithms/bcrypt.py` | bcrypt implementation |
| `hashing/policies/*` | Policy dataclasses + tuning schemas |
| `hashing/factory.py` | Config → policy + façade |
| `hashing/algorithm_registry.py` | Algorithm registry |
| `hashing/policy_registry.py` | Policy registry |
| `hashing/registry.py` | Discovery (`load_all`) |
| `transform/pepper/*` | Pepper strategies/pipeline |
| `utils/config_loader/*` | Deterministic config → objects |
| `bench/*` | Optional benchmarking subsystem |
| `password/*` | Password policy + validator |

---

## 5. Quick Start

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

Enable a pepper strategy:

```bash
export PEPPER_MODE=suffix
export PEPPER_SUFFIX=_S3CRET
```

---

## 6. Configuration & Environment Keys

Example Argon2 keys:

```
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
```

Pepper keys (see section 8):

```
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=SuperStrongPepperKey!!!
# optional: PEPPER_HMAC_ALGO=sha512
```

Factory usage:

```python
from securitykit.hashing.factory import HashingFactory
config = dict(os.environ)
algo = HashingFactory(config).get_algorithm()
policy = HashingFactory(config).get_policy(algo.variant)
```

**Convention:** `{VARIANT}_{PARAM}` uppercased.  
Missing optional keys → policy defaults (warn logged).  
Invalid / out‑of‑range → immediate exception.

---

## 7. Rehash Semantics

| Algorithm | Mechanism |
|-----------|-----------|
| Argon2 | `argon2.PasswordHasher.check_needs_rehash` |
| bcrypt | Parse cost factor from hash and compare to policy |

Pattern:

```python
if algo.needs_rehash(stored_hash):
    stored_hash = algo.hash(plaintext)
```

Notes:
- Malformed hash → logged + returns `False` (conservative)
- Pepper changes alone do **not** drive `needs_rehash`; treat pepper rotation as explicit migration

---

## 8. Pepper Subsystem

Properties:

- Centralized (façade calls pipeline)
- Strategy‑based: `noop`, `prefix`, `suffix`, `prefix_suffix`, `interleave`, `hmac`
- Applied exactly once
- Configured exclusively via `PEPPER_*`

### Keys

| Key | Default | Description |
|-----|---------|-------------|
| `PEPPER_ENABLED` | `true` | Master switch |
| `PEPPER_MODE` | `noop` | Strategy |
| `PEPPER_SECRET` | (empty) | Base secret for simple modes |
| `PEPPER_PREFIX` / `PEPPER_SUFFIX` | (empty) | Explicit overrides |
| `PEPPER_INTERLEAVE_FREQ` | `0` | Insert token every N chars (≤0 noop) |
| `PEPPER_INTERLEAVE_TOKEN` | (empty) | Token for interleave |
| `PEPPER_HMAC_KEY` | (empty) | Required for `hmac` |
| `PEPPER_HMAC_ALGO` | `sha256` | HMAC hash function |

### Strategies

| Mode | Transformation | Strength |
|------|----------------|----------|
| `noop` | none | – |
| `prefix` | `prefix + password` | Obfuscation only |
| `suffix` | `password + suffix` | Obfuscation only |
| `prefix_suffix` | wrap both sides | Obfuscation only |
| `interleave` | insert token at intervals | Weak obfuscation |
| `hmac` | `hex(HMAC(key, pw))` | Cryptographic |

> Only `hmac` provides cryptographic strengthening; others are structured concatenations.

Example:

```bash
export PEPPER_MODE=hmac
export PEPPER_HMAC_KEY='Base64OrRandom32+Chars'
```

---

## 9. Benchmark Interoperability

Policies may define a `BENCH_SCHEMA`:

```python
BENCH_SCHEMA = {
    "time_cost": [2, 3, 4],
    "memory_cost": [65536, 131072],
    "parallelism": [1, 2],
}
```

Process: enumerate → time → score → select → emit config.  
CI tip: reduce candidate lists or monkeypatch timers.

---

## 10. Extending (Policies & Algorithms)

### Policy

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

### Algorithm (raw interface)

```python
from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.policies.scrypt import ScryptPolicy

@register_algorithm("scrypt")
class Scrypt:
    DEFAULT_POLICY_CLS = ScryptPolicy
    def __init__(self, policy: ScryptPolicy | None = None):
        policy = policy or ScryptPolicy()
        if not isinstance(policy, ScryptPolicy):
            raise TypeError("policy must be ScryptPolicy")
        self.policy = policy
    def hash_raw(self, peppered_password: str) -> str: ...
    def verify_raw(self, stored_hash: str, peppered_password: str) -> bool: ...
    def needs_rehash(self, stored_hash: str) -> bool: ...
```

**Façade handles:** pepper, empty password guard, error wrapping.

Checklist:
1. Register policy
2. (Optional) Add `BENCH_SCHEMA`
3. Implement algorithm `hash_raw` / `verify_raw`
4. Implement `needs_rehash`
5. Add tests (roundtrip, param parse, rehash)
6. Pepper diff test (optional)

---

## 11. Error & Exception Model

| Exception | Source | Meaning |
|-----------|--------|---------|
| `HashingError` | Façade | Hash input invalid / delegate failure |
| `VerificationError` | Façade/delegate | Unexpected verify failure |
| `InvalidPolicyConfig` / `ValueError` | Policy init | Invalid parameter |
| `UnknownAlgorithmError` | Registry | No such variant |
| `UnknownPolicyError` | Registry | No such variant |
| `ConfigValidationError` | Config loader | Aggregated conversion/type errors |
| `PepperConfigError` | Pepper builder | Missing required secret/key |
| `PepperStrategyConstructionError` | Strategy build | Unsupported variant/algorithm |

Hash mismatch → `False`, not exception.

---

## 12. Testing Strategy & Patterns

| Test Type | Target |
|-----------|--------|
| Roundtrip | `hash` / `verify` including mismatch |
| Pepper | Hash diff & cross verify failure |
| Param Encoding | Parse Argon2 / bcrypt parameters |
| Rehash | Old policy → stronger policy |
| Error Paths | Empty password, delegate exceptions |
| Config Loader | Conversions + type mismatches |
| Pepper Strategies | Unknown mode fallback, HMAC key edge |
| Bench Smoke | Non‑empty schema enumeration |

---

## 13. Best Practices & Security Notes

| Practice | Reason |
|----------|--------|
| Frozen policies | Prevent silent downgrades |
| Central pepper | Consistency & reduced errors |
| Use HMAC for real peppering | Cryptographic binding |
| Lazy rehash on login | Zero downtime upgrades |
| Rotate pepper with version metadata | Controlled migrations |
| Keep pepper key separate from DB backups | Defense‑in‑depth |
| Log warnings for weak params | Operational visibility |
| Pin crypto lib versions | Avoid semantic shifts |

---

## 14. Migration / “What Changed”

| Old | New |
|-----|-----|
| `Algorithm(..., pepper="X")` | Pepper via `PEPPER_*` |
| Per‑algorithm `_with_pepper` | Central pipeline |
| Implementation `hash()` | `hash_raw`; façade applies pepper |
| Inheritance heavy policies | Frozen dataclasses |
| Manual parametrize duplication | Registry-driven dynamic tests |
| Implicit pepper behavior | Explicit strategy config |

---

## 15. Roadmap

| Item | Status | Notes |
|------|--------|-------|
| Scrypt implementation | Planned | Extend raw pattern |
| Pepper rotation tooling | Planned | Versioned keys / dual verify |
| Multi-hash migration helper | Planned | Legacy → modern |
| Weighted benchmark scoring | Planned | Heuristic tuning |
| Advisory heuristics | Planned | Hardware-aware |
| Hash format compatibility | Investigating | Legacy bcrypt variants |
| Per-user HKDF pepper | Planned | Blast radius reduction |

---

## 16. Appendix: Minimal Manual Flow

```python
from securitykit.hashing.factory import HashingFactory

config = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": f"{64*1024}",
    "ARGON2_PARALLELISM": "2",
}

# Optional pepper
config.update({
    "PEPPER_MODE": "hmac",
    "PEPPER_HMAC_KEY": "ProductionRandom32+ByteKey",
})

algo = HashingFactory(config).get_algorithm()

stored = algo.hash("UserPass123!")
assert algo.verify(stored, "UserPass123!")
if algo.needs_rehash(stored):
    stored = algo.hash("UserPass123!")
```

---

**Questions / Extensions?**  
Open an issue with:
- Variants in use
- Current policy values
- Target latency window
- Hardware/memory constraints
- Pepper mode & rotation plan

The more context you provide, the better recommendations we can give.
