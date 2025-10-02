# SecurityKit API

The `securitykit.api` package provides the *public, stable interface* for the SecurityKit toolkit.  
It consolidates hashing, password policy validation, and rehash management into a cohesive surface that applications can consume without touching internal registries or factories.

---

## Contents

1. Goals
2. Exposed Symbols
3. High-Level Service: `PasswordSecurity`
4. Functional API (Convenience Functions)
5. Construction Patterns
6. Environment Integration
7. Rehash Workflow
8. Error Semantics
9. Minimal End‑to‑End Example
10. Extension Points
11. When to Drop Down to Lower Layers
12. Testing Recommendations
13. Roadmap

---

## 1. Goals

| Goal            | Description                                                             |
|-----------------|-------------------------------------------------------------------------|
| Simplicity      | One object / small function set for common password operations          |
| Safety          | Enforce password policy before hashing                                  |
| Evolvability    | Internal hashing parameters can change; rehash path exposed             |
| Transparency    | Clear separation of invalid password vs hash verification failure       |
| Configuration   | Supports environment- or dict-based initialization                      |

---

## 2. Exposed Symbols

From `securitykit.api` (via `__all__` or `from securitykit.api import ...`):

| Symbol               | Purpose                                           |
|----------------------|---------------------------------------------------|
| `PasswordSecurity`   | High-level service class (stateful)               |
| `hash_password`      | Convenience function: validate + hash             |
| `verify_password`    | Convenience function: verify only                 |
| `rehash_password`    | Convenience function: conditional rehash          |
| `PasswordPolicy`     | Password complexity dataclass                     |
| `PasswordValidator`  | Policy enforcement class                          |
| `Algorithm`          | Hash algorithm façade (lower-level)               |
| `Argon2Policy`       | Built-in hashing policy implementation            |

---

## 3. High-Level Service: `PasswordSecurity`

Methods:

| Method                                   | Behavior |
|------------------------------------------|----------|
| `hash(password: str) -> str`             | Validates password; returns hash string |
| `verify(password: str, stored: str) -> bool` | Compares password with stored hash |
| `needs_rehash(stored: str) -> bool`      | Detects outdated hashing parameters |
| `rehash(password: str, stored: str) -> str` | Returns new hash or original if unchanged |
| `validate(password: str) -> None`        | Raises if password violates policy |
| `from_env(cls)`                          | Build service using environment variables |
| `from_mapping(cls, mapping: Mapping)`    | Build from arbitrary mapping/dict |

Composition:

- Internally builds:
  - A hashing algorithm (via registry + factory)
  - A password validator (with configured `PasswordPolicy`)

---

## 4. Functional API (Convenience Functions)

For very small integrations (no object lifecycle):

```python
from securitykit.api import hash_password, verify_password, rehash_password

h = hash_password("StrongExample1!")
assert verify_password("StrongExample1!", h)
maybe_new = rehash_password("StrongExample1!", h)
```

These functions:
- Use a process-wide cached internal `PasswordSecurity` instance
- Rebuild implicitly when environment changes (if you trigger a reload pattern)
- Are ideal for scripts or lightweight services

---

## 5. Construction Patterns

### Default (environment-driven)

```python
from securitykit.api import PasswordSecurity
service = PasswordSecurity.from_env()
```

### Custom mapping (e.g. test fixture)

```python
config = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "65536",
    "ARGON2_PARALLELISM": "2",
    "PASSWORD_MIN_LENGTH": "12",
}
service = PasswordSecurity.from_mapping(config)
```

### Injecting a pepper (advanced)

If you need to force a custom pepper (instead of environment):

```python
service = PasswordSecurity.from_env()
service.algorithm = type(service.algorithm)(
    service.algorithm.variant,
    service.algorithm.policy,
    pepper="SERVER_SIDE_STATIC_OR_ROTATED_SECRET",
)
```

(You can also rebuild the underlying algorithm through the lower-level factory.)

---

## 6. Environment Integration

Expected keys (variant-specific subset depends on the hashing policy):

| Key                                | Purpose |
|------------------------------------|---------|
| `HASH_VARIANT`                     | Select hashing implementation (e.g. `argon2`) |
| `ARGON2_TIME_COST`                 | Argon2 parameter |
| `ARGON2_MEMORY_COST`               | Argon2 parameter (bytes) |
| `ARGON2_PARALLELISM`               | Argon2 threads/lanes |
| `ARGON2_HASH_LENGTH`               | Hash output length |
| `ARGON2_SALT_LENGTH`               | Salt length |
| `PEPPER_VALUE` (optional)          | Global pepper (not stored with hash) |
| `PASSWORD_MIN_LENGTH`              | Policy minimum length |
| `PASSWORD_REQUIRE_UPPER`           | Policy boolean |
| `PASSWORD_REQUIRE_LOWER`           | Policy boolean |
| `PASSWORD_REQUIRE_DIGIT`           | Policy boolean |
| `PASSWORD_REQUIRE_SPECIAL`         | Policy boolean |

When incomplete and `AUTO_BENCHMARK=1`, the bootstrap subsystem may auto-generate missing hashing parameters into `.env.local`.

---

## 7. Rehash Workflow

Typical application flow (e.g. during login):

```python
from securitykit.api import verify_password, rehash_password

if verify_password(candidate, stored_hash):
    new_hash = rehash_password(candidate, stored_hash)
    if new_hash != stored_hash:
        # Persist updated hash (parameters improved)
        update_user_hash(new_hash)
```

Why: Parameter evolution (e.g., increasing Argon2 time cost) can be rolled out gradually.

---

## 8. Error Semantics

| Situation                               | Raised / Returned |
|-----------------------------------------|-------------------|
| Password fails complexity               | `InvalidPolicyConfig` |
| Hash verification mismatch              | `False` from `verify` |
| Hash parsing error (corrupt input)      | Safe `False` (verify) or `needs_rehash=True` (implementation dependent) |
| Missing required config for hashing     | `ConfigValidationError` during construction |
| Unsupported `HASH_VARIANT`              | Error logged + raise during initialization |

The API keeps cryptographic failures (verify returns `False`) distinct from configuration or policy failures (exceptions).

---

## 9. Minimal End‑to‑End Example

```python
from securitykit.api import PasswordSecurity
from securitykit.exceptions import InvalidPolicyConfig

service = PasswordSecurity.from_mapping({
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "65536",
    "ARGON2_PARALLELISM": "2",
    "PASSWORD_MIN_LENGTH": "12",
    "PASSWORD_REQUIRE_UPPER": "true",
    "PASSWORD_REQUIRE_DIGIT": "true",
    "PASSWORD_REQUIRE_SPECIAL": "false",
})

try:
    digest = service.hash("ValidPass123")
    assert service.verify("ValidPass123", digest)
    updated = service.rehash("ValidPass123", digest)
    # updated is either identical or a new hash if parameters changed
except InvalidPolicyConfig as e:
    print("Policy violation:", e)
```

---

## 10. Extension Points

| Need                           | Approach |
|--------------------------------|----------|
| Custom hashing implementation  | Register new algorithm + policy in `securitykit.hashing` |
| Custom password policy fields  | Extend `PasswordPolicy` and supply your own validator |
| Custom config source           | Use lower-level factories / config loader directly |
| Pepper rotation                | Wrap `hash` + `verify` in migration routine, then swap pepper |

---

## 11. When to Drop Down to Lower Layers

| Use Case                                | Drop To |
|-----------------------------------------|---------|
| Benchmarking / tuning                   | `securitykit.bench` CLI or API |
| Fine-grained hashing parameter control  | `hashing.factory.HashingFactory` |
| Config introspection / documentation    | `utils.config_loader.export_schema` |
| Custom algorithm or policy registration | Registries in `hashing/*` |

---

## 12. Testing Recommendations

| Test Focus               | Strategy |
|--------------------------|----------|
| Hash + verify roundtrip  | Use deterministic password; assert verify returns True |
| Policy violation         | Intentionally weak password; assert `InvalidPolicyConfig` |
| Rehash path              | Hash with old policy → raise parameter → assert `rehash` returns different hash |
| Environment-based init   | Provide a minimal mapping; avoid relying on real OS env in tests |
| Corrupt hash handling    | Pass malformed hash to `verify`; expect `False` (no exception) |

Example pytest snippet:

```python
def test_high_level_roundtrip():
    from securitykit.api import PasswordSecurity
    svc = PasswordSecurity.from_mapping({
        "HASH_VARIANT": "argon2",
        "ARGON2_TIME_COST": "2",
        "ARGON2_MEMORY_COST": "65536",
        "ARGON2_PARALLELISM": "1",
        "PASSWORD_MIN_LENGTH": "8",
    })
    pwd = "Abcdef1!"
    h = svc.hash(pwd)
    assert svc.verify(pwd, h)
```

---

## 13. Roadmap

| Planned Feature                 | Intent |
|---------------------------------|--------|
| Async `PasswordSecurityAsync`   | Non-blocking I/O integration (e.g. ASGI frameworks) |
| Framework adapters              | FastAPI / Flask / Django helper utilities |
| Multi-hash migration utility    | Seamless upgrade from legacy bcrypt/PBKDF2 to Argon2 |
| Pepper rotation assist          | Transitional verify+rehash helper |
| Structured metrics hooks        | Observability (hash counts, rehash triggers) |

---

## Summary

`securitykit.api` is the stable perimeter of the library.  
Internal layout (registries, factories, benchmarking) can evolve, while the API layer preserves a consistent developer experience for hashing, validating, and upgrading password credentials.

For deeper customization, read the individual subsystem READMEs (hashing, password, config loader, bench).
