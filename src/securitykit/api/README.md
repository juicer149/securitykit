# SecurityKit API

The `securitykit.api` package is the *stable public surface* of SecurityKit.

It exposes high‑level password functions, the hashing façade, policies, and registry helpers without requiring direct imports of internal modules. Pepper handling is centralized and configuration‑driven (`PEPPER_*`), and algorithm implementations are wrapped by a façade that enforces validation and applies pepper exactly once.

---

## Table of Contents

1. Goals  
2. Exported Symbols  
3. Architecture (API Layer)  
4. Functional Convenience API  
5. Algorithm Façade & Factory  
6. Pepper Configuration (`PEPPER_*`)  
7. Rehash Workflow  
8. Error & Return Semantics  
9. Configuration Examples  
10. End‑to‑End Example  
11. When to Use Lower Layers  
12. Testing Patterns  
13. Migration (Removed / Changed)  
14. Roadmap  
15. Summary  

---

## 1. Goals

| Goal | Description |
|------|-------------|
| Simplicity | Small set of functions for typical password flows |
| Safety | Enforces password policy before hashing |
| Evolvability | Hash parameters can be raised over time (rehash path exposed) |
| Transparency | Distinguishes policy errors vs. mismatches |
| Configurability | Environment or arbitrary mapping supported |
| Consistency | Single pepper subsystem (no per‑algorithm pepper code) |

---

## 2. Exported Symbols

From `securitykit.api` (lazy‑loaded):

| Symbol | Purpose |
|--------|---------|
| `hash_password` | Validate + hash |
| `verify_password` | Verify only (returns `False` on mismatch) |
| `rehash_password` | Conditional upgrade hash |
| `Algorithm` | High‑level façade (`hash`, `verify`, `needs_rehash`) |
| `HashingFactory` | Build policy + façade from a config mapping |
| `register_algorithm`, `list_algorithms`, `get_algorithm_class` | Algorithm registry |
| `register_policy`, `list_policies`, `get_policy_class` | Policy registry |
| `Argon2Policy`, `BcryptPolicy` | Built‑in hashing policies |
| `PasswordPolicy` | Password complexity policy |
| `PasswordValidator` | Enforces password policy |

> The legacy `PasswordSecurity` class has been removed. Use the functions or the `Algorithm` façade directly.

---

## 3. Architecture (API Layer)

```
App code
  ↓
securitykit.api (hash_password / verify_password / rehash_password)
  ↓
Algorithm façade (pepper application + guards + error wrapping)
  ↓
Concrete implementation (hash_raw / verify_raw)
  ↓
Underlying crypto library (argon2-cffi, bcrypt, ...)
```

Pepper is applied exactly once inside the façade based on `PEPPER_*` keys.

---

## 4. Functional Convenience API

```python
from securitykit.api import hash_password, verify_password, rehash_password

h = hash_password("StrongExample1!")
assert verify_password("StrongExample1!", h)
maybe_new = rehash_password("StrongExample1!", h)
```

---

## 5. Algorithm Façade & Factory

```python
from securitykit.api import Algorithm, HashingFactory
from securitykit.hashing.policies.argon2 import Argon2Policy

facade = Algorithm("argon2", policy=Argon2Policy(time_cost=3))
digest = facade.hash("Abcdef1!")
assert facade.verify(digest, "Abcdef1!")
```

Via the factory:

```python
config = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "65536",
    "ARGON2_PARALLELISM": "2",
}
algo = HashingFactory(config).get_algorithm()
```

---

## 6. Pepper Configuration (`PEPPER_*`)

Pepper is only configured via environment (or mapping) keys:

| Key | Default | Description |
|-----|---------|-------------|
| `PEPPER_ENABLED` | `true` | Master switch |
| `PEPPER_MODE` | `noop` | One of `noop|prefix|suffix|prefix_suffix|interleave|hmac` |
| `PEPPER_SECRET` | (empty) | Base/fallback secret for simple modes |
| `PEPPER_PREFIX` / `PEPPER_SUFFIX` | (empty) | Override prefix/suffix explicitly |
| `PEPPER_INTERLEAVE_FREQ` | `0` | >0 inserts token every N chars |
| `PEPPER_INTERLEAVE_TOKEN` | (empty) | Interleave sequence (fallback: `PEPPER_SECRET`) |
| `PEPPER_HMAC_KEY` | (empty) | Required for `hmac` |
| `PEPPER_HMAC_ALGO` | `sha256` | Hash function for HMAC |

Example (HMAC):

```bash
export PEPPER_MODE=hmac
export PEPPER_HMAC_KEY='Random32ByteLikeKeyHere'
```

---

## 7. Rehash Workflow

Typical login flow:

```python
from securitykit.api import verify_password, rehash_password

if verify_password(candidate, stored_hash):
    new_hash = rehash_password(candidate, stored_hash)
    if new_hash != stored_hash:
        persist(new_hash)
```

---

## 8. Error & Return Semantics

| Situation | Behavior |
|-----------|----------|
| Password violates policy | Exception from validator |
| Hash mismatch | `False` on `verify_password` |
| Corrupt hash format | `False` (conservative) + logged warning |
| Unknown algorithm variant | Exception during construction |
| Invalid config type/value | `ConfigValidationError` |
| Pepper config missing HMAC key in `hmac` mode | Pepper-specific config exception |

Password mismatch vs. system/config errors are clearly separated.

---

## 9. Configuration Examples

```env
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=ChangeMeStrong
PASSWORD_MIN_LENGTH=10
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_SPECIAL=true
```

---

## 10. End‑to‑End Example

```python
from securitykit.api import hash_password, verify_password

digest = hash_password("StrongPass9!")
assert verify_password("StrongPass9!", digest)
```

With pepper:

```python
import os
os.environ["PEPPER_MODE"] = "suffix"
os.environ["PEPPER_SUFFIX"] = "_SrvPep"

from securitykit.api import hash_password
h = hash_password("StrongPass9!")
```

---

## 11. When to Use Lower Layers

| Need | Layer |
|------|-------|
| Performance tuning / benchmarking | `securitykit.hashing.bench` (if enabled) |
| Fine-grained policy construction | `HashingFactory` |
| Custom configuration loading | `utils.config_loader` |
| Adding new algorithm or policy | `register_algorithm` / `register_policy` |

---

## 12. Testing Patterns

| Test | Pattern |
|------|--------|
| Roundtrip | `hash_password` → `verify_password` |
| Policy violation | Weak password → expect exception |
| Rehash path | Hash → raise param → `rehash_password` returns different hash |
| Pepper difference | Compare hash with vs. without `PEPPER_*` |
| Edge empty password | Expect exception on hashing |
| Config validation | Wrong type → `ConfigValidationError` |

---

## 13. Migration (Removed / Changed)

| Legacy | Current |
|--------|---------|
| `PasswordSecurity` class | Functional API + `Algorithm` façade |
| `pepper=` arg on algorithms | `PEPPER_*` strategy-based system |
| Per‑algorithm pepper code | Central pipeline |
| Direct `hash()` in implementation | `hash_raw`/`verify_raw` + façade for pepper |
| Ad hoc test parametrization | Dynamic discovery + registries |

---

## 14. Roadmap

| Feature | Status |
|---------|--------|
| Pepper version/rotation (`PEPPER_VERSION`) | Planned |
| Scrypt / PBKDF2 support | Planned |
| Multi‑hash migration helper | Planned |
| Observability / metrics hooks | Planned |
| Async API variant | Investigating |
| Hardware advisory suggestions | Planned |

---

## 15. Summary

The API layer is a lean, stable front:
- Configuration → Factory → Façade
- Central pepper strategies
- Policy enforcement before hashing
- Straightforward rehash flow

Use this layer for most application integrations; drop to lower layers only for tuning, extension, or custom config flows.
