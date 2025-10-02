# SecurityKit Hashing

The `securitykit.hashing` package provides the core abstractions for password hashing:
a uniform `Algorithm` façade, policy dataclasses with validation and (optionally) benchmark
schemas, and registry / factory utilities for discovering and constructing implementations.

---

## Contents

1. Goals
2. Core Concepts
3. Public Modules
4. Quick Start
5. Configuration Integration
6. Rehashing Semantics
7. Pepper Support
8. Benchmark Interoperability
9. Extending (Algorithms / Policies)
10. Factory Usage Patterns
11. Error Handling
12. Testing Guidance
13. Best Practices
14. Roadmap

---

## 1. Goals

| Goal              | Description                                                  |
|-------------------|--------------------------------------------------------------|
| Uniform Interface | One `Algorithm` object exposes `hash`, `verify`, `needs_rehash` |
| Safety            | Policy validation enforces numeric bounds and consistency   |
| Extensibility     | New algorithms/policies registered via decorators           |
| Determinism       | Construction controlled entirely by explicit config         |
| Benchmark Ready   | Policies can declare `BENCH_SCHEMA` for tuning              |
| Separation        | Algorithms encapsulate cryptographic operations; policies define parameters |

---

## 2. Core Concepts

| Concept    | Description |
|------------|-------------|
| Algorithm  | High-level façade created from a variant + policy (and optional pepper) |
| Policy     | Dataclass capturing parameter set; validates in `__post_init__`; may define `BENCH_SCHEMA` |
| Registry   | Maps variant name → algorithm class (`algorithm_registry`) or policy class (`policy_registry`) |
| Factory    | Builds a policy + algorithm from configuration keys (e.g. `HASH_VARIANT=argon2`, `ARGON2_TIME_COST=3`) |
| BENCH_SCHEMA | Dict[str, list[BenchValue]] enumerating dimensions for benchmarking/tuning |
| Pepper     | Optional secret value appended (or otherwise incorporated) before hashing |

---

## 3. Public Modules

| Module/File                           | Purpose |
|--------------------------------------|---------|
| `hashing/algorithm.py`               | `Algorithm` façade and protocol integration |
| `hashing/algorithms/argon2.py`       | Built‑in Argon2id implementation |
| `hashing/policies/argon2.py`         | `Argon2Policy` dataclass + validation + `BENCH_SCHEMA` |
| `hashing/algorithm_registry.py`      | Registration decorators / lookup for algorithms |
| `hashing/policy_registry.py`         | Registration decorators / lookup for policies |
| `hashing/factory.py`                 | `HashingFactory` (policy + algorithm instantiation) |
| `hashing/registry.py`                | Auto-loader (`load_all`) for discovery |
| `hashing/interfaces.py`              | Protocols / typing contracts (e.g. `AlgorithmProtocol`) |

---

## 4. Quick Start

```python
from securitykit.hashing import Algorithm
from securitykit.hashing.policies.argon2 import Argon2Policy

policy = Argon2Policy(time_cost=3, memory_cost=65536, parallelism=2)
algo = Algorithm("argon2", policy, pepper="OPTIONAL_GLOBAL_PEPPER")

digest = algo.hash("CorrectHorseBatteryStaple!")
assert algo.verify(digest, "CorrectHorseBatteryStaple!")

if algo.needs_rehash(digest):
    # Re-hash with new parameters if they changed
    digest = algo.hash("CorrectHorseBatteryStaple!")
```

---

## 5. Configuration Integration

Typical environment-driven instantiation uses the high-level factory:

```python
from securitykit.hashing.factory import HashingFactory

env_map = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "65536",
    "ARGON2_PARALLELISM": "2",
}

factory = HashingFactory(env_map)
algo = factory.get_algorithm()        # Policy resolved automatically
policy = factory.get_policy()         # Access the policy directly if needed
```

All variant-specific keys:
```
ARGON2_TIME_COST
ARGON2_MEMORY_COST
ARGON2_PARALLELISM
ARGON2_HASH_LENGTH
ARGON2_SALT_LENGTH
```
Missing optional parameters fall back to policy defaults with a warning. Missing required parameters raise a configuration error.

---

## 6. Rehashing Semantics

`Algorithm.needs_rehash(stored_hash)` returns `True` if the existing encoded hash does not match current policy parameters (e.g. higher `time_cost`, longer hash length). Typical flow:

```python
stored_hash = user_record.password_hash
if algo.needs_rehash(stored_hash):
    new_hash = algo.hash(plain_password)
    # Persist new_hash
```

The high-level API (`securitykit.api.rehash_password`) wraps this pattern for convenience.

---

## 7. Pepper Support

Algorithms accept an optional `pepper` (server-side secret). It should:
- Come from a secure secret manager
- Not be stored alongside user hashes
- Be stable across the lifetime of existing hashes (rotation requires migration strategy)

Pepper usage pattern:
```python
algo = Algorithm("argon2", policy, pepper=PEPPER_VALUE)
```

---

## 8. Benchmark Interoperability

Policies that define a `BENCH_SCHEMA`:

```python
class Argon2Policy(...):
    BENCH_SCHEMA = {
        "time_cost": [2, 3, 4],
        "memory_cost": [65536, 131072],
        "parallelism": [1, 2],
    }
```

The benchmarking subsystem:
1. Enumerates all combinations
2. Times hashing
3. Selects a “best” configuration based on target time (balanced or closest)
4. Produces an `.env.local` with tuned values
5. Adds integrity metadata (`GENERATED_SHA256`) for bootstrap validation

---

## 9. Extending

### New Policy

```python
from dataclasses import dataclass
from securitykit.hashing.policy_registry import register_policy

@register_policy("bcrypt")
@dataclass
class BcryptPolicy:
    cost: int = 12
    BENCH_SCHEMA = {"cost": [10, 12, 14]}

    def __post_init__(self):
        if self.cost < 4 or self.cost > 31:
            raise ValueError("bcrypt cost out of accepted range")
```

### New Algorithm

```python
from securitykit.hashing.algorithm_registry import register_algorithm
from securitykit.hashing.interfaces import AlgorithmProtocol

@register_algorithm("bcrypt")
class Bcrypt(AlgorithmProtocol):
    def __init__(self, policy, pepper: str | None = None):
        self.policy = policy
        self.pepper = pepper

    def hash(self, password: str) -> str:
        # combine pepper if provided; delegate to bcrypt lib
        ...

    def verify(self, stored_hash: str, password: str) -> bool:
        ...

    def needs_rehash(self, stored_hash: str) -> bool:
        # parse bcrypt cost and compare with policy.cost
        ...
```

### Registration Notes

- Variant names must be unique (case-insensitive)
- Decorators enforce no duplicate registration
- Algorithms must satisfy the `AlgorithmProtocol` interface

---

## 10. Factory Usage Patterns

| Use Case                | Approach |
|-------------------------|----------|
| Standard initialization | `HashingFactory(os.environ).get_algorithm()` |
| Inspect policy only     | `factory.get_policy()` |
| Custom pepper injection | Build policy, then `Algorithm(variant, policy, pepper=...)` |
| Testing overrides       | Provide a minimal dict with just relevant keys |

---

## 11. Error Handling

| Error Type / Scenario      | Raised / Logged |
|----------------------------|-----------------|
| Missing required policy keys | `ConfigValidationError` (via config loader) |
| Invalid parameter value       | `ValueError` inside policy → wrapped in `ConfigValidationError` via factory |
| Unregistered variant          | Lookup error in registry → surfaced from factory |
| Rehash parsing error          | `needs_rehash` implementations should return `True` or `False`; log anomalies |

---

## 12. Testing Guidance

Recommended isolation patterns:

| Pattern | Purpose |
|---------|---------|
| Snapshot registries before test | Avoid leaking temporary variants |
| Patch hash function for speed | Keep timing tests fast and deterministic |
| Parametrize policy edge values | Boundary coverage (min/max) |
| Roundtrip test | `hash` then `verify` (valid + invalid password) |
| Rehash test | Hash with old parameters → increase one parameter → assert `needs_rehash` |

Example fixture (conceptual):
```python
@pytest.fixture
def fast_algo(monkeypatch):
    from securitykit.hashing.algorithm import Algorithm
    # monkeypatch underlying library call if needed
```

---

## 13. Best Practices

| Practice | Rationale |
|----------|-----------|
| Keep policy constructors free of side-effects | Easier validation and testing |
| Validate numeric bounds in `__post_init__`    | Fail early, explicit error paths |
| Avoid embedding environment reads in algorithms | Use factory or high-level API |
| Rehash opportunistically on login             | Gradual fleet upgrade without bulk jobs |
| Separate pepper management from config        | Secrets belong in secret stores, not static files |
| Use benchmark output for production defaults  | Ground parameter selection in target latency |

---

## 14. Roadmap

| Planned | Description |
|---------|-------------|
| Additional algorithms | bcrypt, scrypt, PBKDF2 implementations |
| Migration helpers     | Multi-hash support (e.g. accept old → upgrade to new) |
| Parameter advisory    | Heuristics recommending stronger settings based on hardware |
| Weighted analyzer     | Allow performance vs memory tradeoff modes |
| Pluggable encoders    | Support alternate on-disk hash formats |

---

## Appendix: Minimal Manual Flow

```python
from securitykit.hashing.factory import HashingFactory

# 1. Provide configuration (env or dict)
config = {
    "HASH_VARIANT": "argon2",
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "65536",
    "ARGON2_PARALLELISM": "2",
}

# 2. Build algorithm
algo = HashingFactory(config).get_algorithm()

# 3. Hash user password
stored = algo.hash("UserPass123!")

# 4. Verify later
if algo.verify(stored, "UserPass123!"):
    print("Authenticated")

# 5. Rehash if parameters changed
if algo.needs_rehash(stored):
    stored = algo.hash("UserPass123!")
```

---

This hashing layer integrates upward (via `securitykit.api`) and downward (with configurable factories and registries), enabling controlled evolution of hashing strategies without invasive code changes elsewhere.
