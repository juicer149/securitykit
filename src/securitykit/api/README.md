# SecurityKit API

The `securitykit.api` package is the stable public surface of SecurityKit.

It exposes high‑level password functions, the hashing façade, policies, and registry helpers without requiring direct imports of internal modules. Pepper handling is centralized and configuration‑driven (`PEPPER_*`), and algorithm implementations are wrapped by a façade that applies pepper exactly once, enforces input validation, and centralizes cross‑variant tolerance.

The API module is lazy‑loaded: symbols are resolved on demand to keep imports fast and side‑effect free.

---

## Table of Contents

1. Goals  
2. Exported Symbols  
3. Architecture (API Layer)  
4. Functional Convenience API  
5. Algorithm Façade & Factory  
6. Pepper Configuration (`PEPPER_*`)  
7. Rehash and Upgrade Workflow  
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
| Safety | Policy dataclasses validate and guard before hashing |
| Evolvability | Hash parameters can be raised over time (rehash path) |
| Transparency | Clear separation between mismatches and system/config errors |
| Configurability | Environment or arbitrary mapping (`dict`) supported |
| Consistency | Single pepper subsystem (no per‑algorithm pepper code) |
| Minimal Core | Algorithms installed via extras; conditional registration |

---

## 2. Exported Symbols

From `securitykit.api` (lazy‑loaded):

| Symbol | Purpose |
|--------|---------|
| `hash_password` | Validate + hash |
| `verify_password` | Verify only (returns `False` on mismatch) |
| `rehash_password` | Conditional upgrade (same variant, stricter policy) |
| `authenticate_and_upgrade` | Login‑time verify + migrate (cross‑variant) |
| `Algorithm` | High‑level façade (`hash`, `verify`, `needs_rehash`) |
| `HashingFactory` | Build policy + façade from a config mapping |
| `register_algorithm`, `list_algorithms`, `get_algorithm_class` | Algorithm registry |
| `register_policy`, `list_policies`, `get_policy_class` | Policy registry |
| `Argon2Policy`, `BcryptPolicy`, `ScryptPolicy`, `WerkzeugPBKDF2Policy` | Built‑in hashing policies |
| `PasswordPolicy`, `PasswordValidator` | Password complexity policy and validator |

Notes:
- Variants are registered conditionally depending on installed extras (e.g., Argon2 requires `securitykit[alg_argon2]`).
- The legacy `PasswordSecurity` class has been removed. Use the functions or the `Algorithm` façade.

---

## 3. Architecture (API Layer)

```
Application
  ↓
securitykit.api (hash_password / verify_password / rehash_password / authenticate_and_upgrade)
  ↓
Algorithm façade (pepper application + guards + error wrapping + cross-variant tolerance)
  ↓
Concrete implementation (hash_raw / verify_raw / needs_rehash)
  ↓
Underlying crypto library (argon2-cffi, bcrypt, hashlib.scrypt, werkzeug.security)
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

Login‑time cross‑variant migration (e.g., bcrypt → Argon2):
```python
from securitykit.api import authenticate_and_upgrade

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

## 5. Algorithm Façade & Factory

```python
from securitykit.api import Algorithm, HashingFactory
from securitykit.hashing.policies.argon2 import Argon2Policy

facade = Algorithm("argon2", policy=Argon2Policy(time_cost=3, memory_cost=65536, parallelism=2))
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

Factory also constructs the typed policy for a variant:
```python
policy = HashingFactory(config).get_policy(algo.variant)
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

## 7. Rehash and Upgrade Workflow

Same‑variant policy upgrade during login:
```python
from securitykit.api import verify_password, rehash_password

if verify_password(candidate, stored_hash):
    new_hash = rehash_password(candidate, stored_hash)
    if new_hash != stored_hash:
        persist(new_hash)
```

Cross‑variant migration during login (e.g., Werkzeug PBKDF2 → Argon2):
```python
from securitykit.api import authenticate_and_upgrade

ok, new_hash = authenticate_and_upgrade(candidate, stored_hash, config=dest_cfg)
if ok and new_hash is not None:
    persist(new_hash)
```

Behavior:
- If the destination variant equals the stored hash’s variant, rehash occurs only if `needs_rehash=True`.
- If the destination variant differs, a new hash is always produced on successful authentication.

---

## 8. Error & Return Semantics

| Situation | Behavior |
|-----------|----------|
| Policy construction error | Exception from policy validation |
| Hash mismatch | `False` from `verify_password` / `authenticate_and_upgrade` returns `(False, None)` |
| Foreign variant verified with wrong algorithm | Central façade detects and returns `False` (no exception) |
| Malformed hash of same variant | Surfaces as `VerificationError` (diagnostic) |
| Unknown algorithm variant | `UnknownAlgorithmError` during construction |
| Invalid config type/value | `ConfigValidationError` (from config loader) |
| Pepper config missing key in `hmac` mode | Pepper‑specific configuration exception |

This separation makes it clear when credentials are wrong versus when the system or configuration is incorrect.

---

## 9. Configuration Examples

```env
# Select algorithm and policy
HASH_VARIANT=argon2
ARGON2_TIME_COST=3
ARGON2_MEMORY_COST=65536
ARGON2_PARALLELISM=2
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16

# Pepper
PEPPER_MODE=hmac
PEPPER_HMAC_KEY=ChangeMeStrong

# Password policy (example)
PASSWORD_MIN_LENGTH=10
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_SPECIAL=true
```

scrypt:
```env
HASH_VARIANT=scrypt
SCRYPT_N=16384
SCRYPT_R=8
SCRYPT_P=1
SCRYPT_SALT_LENGTH=16
SCRYPT_HASH_LENGTH=32
# OpenSSL memory cap (bytes); default 512 MiB
SCRYPT_MAXMEM=536870912
```

Werkzeug PBKDF2:
```env
HASH_VARIANT=werkzeug_pbkdf2
WERKZEUG_PBKDF2_METHOD=pbkdf2:sha256
WERKZEUG_PBKDF2_ITERATIONS=260000
WERKZEUG_PBKDF2_SALT_LENGTH=16
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

Cross‑variant login upgrade:
```python
from securitykit.api import authenticate_and_upgrade

dest_cfg = {"HASH_VARIANT": "argon2", "ARGON2_TIME_COST": 3, "ARGON2_MEMORY_COST": 131072, "ARGON2_PARALLELISM": 2}
ok, new_hash = authenticate_and_upgrade(password, user.password_hash, config=dest_cfg)
if ok and new_hash is not None:
    persist(new_hash)
```

---

## 11. When to Use Lower Layers

| Need | Layer |
|------|-------|
| Performance tuning / benchmarking | `securitykit.bench` (if enabled) |
| Fine‑grained policy construction | `HashingFactory` |
| Custom configuration loading | `utils.config_loader` |
| Adding a new algorithm or policy | `register_algorithm` / `register_policy` |
| Variant detection utilities | `hashing.utils.detect_variant` |

---

## 12. Testing Patterns

| Test | Pattern |
|------|--------|
| Roundtrip | `hash_password` → `verify_password` (match and mismatch) |
| Policy violation | Weak password → expect exception |
| Rehash path | Hash → raise params → `rehash_password` returns different hash |
| Cross‑variant verify tolerance | Verify stored hash with a different variant → expect `False` (no exception) |
| Migration | `authenticate_and_upgrade` across all variant pairs |
| Pepper difference | Compare hash with vs. without `PEPPER_*` |
| Edge empty password | Expect exception on hashing |
| Config validation | Wrong type → `ConfigValidationError` |

---

## 13. Migration (Removed / Changed)

| Legacy | Current |
|--------|---------|
| `PasswordSecurity` class | Functional API + `Algorithm` façade |
| `pepper=` per algorithm | Central, strategy‑based `PEPPER_*` |
| Implementation `hash()` | `hash_raw`/`verify_raw` in implementations; façade applies pepper |
| Eager, fixed algorithms | Conditional registration; algorithms as extras |
| Cross‑variant errors | Central tolerance: foreign variant → `False` |
| No login migration helper | `authenticate_and_upgrade(password, stored_hash, config)` |

If a variant is missing (`UnknownAlgorithmError`), install the relevant extra, e.g.:
- Argon2: `pip install "securitykit[alg_argon2]"`
- bcrypt: `pip install "securitykit[alg_bcrypt]"`
- Werkzeug PBKDF2: `pip install "securitykit[alg_werkzeug]"`

---

## 14. Roadmap

| Feature | Status |
|---------|--------|
| Login‑time migration helper | Shipped (`authenticate_and_upgrade`) |
| scrypt support with OpenSSL cap control | Shipped (`SCRYPT_MAXMEM`) |
| Werkzeug PBKDF2 support | Shipped (`WERKZEUG_PBKDF2_*`) |
| Pepper version/rotation (`PEPPER_VERSION`) | Planned |
| Weighted benchmark scoring | Planned |
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
- Seamless login‑time migration across variants

Use this layer for most application integrations; drop to lower layers only for tuning, extension, or custom config flows.
