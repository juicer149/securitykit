# Pepper Subsystem (Diagnostics‑Aware)

Centralized, configuration‑driven transformation applied to a plaintext password before it is passed to any hashing algorithm. Algorithms (Argon2, bcrypt, etc.) do not handle pepper directly — the PepperFactory determines how and where to apply it based on runtime capabilities (diagnostics).

The design is variant‑agnostic, late‑bound to the diagnostics registry, and integrates seamlessly with the Algorithm façade.

---

## Table of Contents

1. Rationale
2. Quick Start
3. Configuration (`PEPPER_*`)
4. Strategy Overview
5. HMAC Mode and Native Secret
6. Interleave Mode
7. Examples
8. Integration with the Hashing Façade
9. Diagnostics & Capability Awareness
10. Caching and Lazy Loading
11. Error Handling and Fallback Behavior
12. Security Guidance
13. Extending (Custom Strategy)
14. Deployment Checklist
15. Roadmap

---

## 1. Rationale

| Goal                   | Description                                                                                               |
| ---------------------- | --------------------------------------------------------------------------------------------------------- |
| Central Decision Point | One place (the factory) decides how and when pepper is applied.                                           |
| Config‑Driven          | Behavior controlled exclusively via `PEPPER_*` keys.                                                      |
| Diagnostics‑Aware      | Uses algorithm diagnostics (`extra['supports_secret']`) to choose native vs external peppering.           |
| Extensible             | Add new strategies without touching existing algorithms.                                                  |
| Safe Defaults          | For UI pipelines, failures degrade to noop with logging; for factory construction, invalid config raises. |
| Auditable              | All fallbacks and warnings go through centralized logging.                                                |

---

## 2. Quick Start

```python
import os
from securitykit.transform.pepper.factory import PepperFactory

os.environ.update({
    "PEPPER_MODE": "hmac",
    "PEPPER_HMAC_KEY": "SuperStrongPepperKey!!!",
})

# Example for Argon2 (diagnostics-driven)
app = PepperFactory.from_config("argon2", os.environ)
# If Argon2 supports native secret:
# PepperApplication(prehash_pipeline=None, algo_kwargs={'secret': b'SuperStrongPepperKey!!!'})

# Example for bcrypt (no native secret support):
app_bcrypt = PepperFactory.from_config("bcrypt", os.environ)
# PepperApplication(prehash_pipeline=<callable>, algo_kwargs={})
```

If the installed Argon2 version supports the native `secret` parameter (argon2‑cffi ≥ 21.3.0), the pepper key is injected directly into the algorithm. Otherwise, SecurityKit transparently applies an HMAC prehash before hashing.

Note: In normal application flows you will not call `PepperFactory` directly; the `Algorithm` façade does this automatically on construction.

---

## 3. Configuration (`PEPPER_*`)

| Variable                  | Type | Default  | Description                                                               |
| ------------------------- | ---- | -------- | ------------------------------------------------------------------------- |
| `PEPPER_ENABLED`          | bool | `true`   | Master switch                                                             |
| `PEPPER_MODE`             | str  | `noop`   | One of: `noop`, `prefix`, `suffix`, `prefix_suffix`, `interleave`, `hmac` |
| `PEPPER_SECRET`           | str  | `""`     | Generic base secret for simple modes                                      |
| `PEPPER_PREFIX`           | str  | `""`     | Explicit prefix override                                                   |
| `PEPPER_SUFFIX`           | str  | `""`     | Explicit suffix override                                                   |
| `PEPPER_INTERLEAVE_FREQ`  | int  | `0`      | Insert token every N chars (≤ 0 → noop)                                   |
| `PEPPER_INTERLEAVE_TOKEN` | str  | `""`     | Token for interleave mode                                                 |
| `PEPPER_HMAC_KEY`         | str  | `""`     | Required for HMAC mode                                                    |
| `PEPPER_HMAC_ALGO`        | str  | `sha256` | Digest algorithm for HMAC                                                 |

Notes
- The config loader is strict: for booleans use `true/false`, not `1/0`.
- Precedence in simple modes: explicit prefix/suffix > `PEPPER_SECRET`.

---

## 4. Strategy Overview

| Mode            | Transformation                  | Category          |
| --------------- | ------------------------------- | ----------------- |
| `noop`          | Identity                        | None              |
| `prefix`        | `prefix + password`             | Obfuscation       |
| `suffix`        | `password + suffix`             | Obfuscation       |
| `prefix_suffix` | `prefix + password + suffix`    | Obfuscation       |
| `interleave`    | Insert token every N characters | Weak obfuscation  |
| `hmac`          | `hex(HMAC(key, password))`      | Cryptographic     |

Only `hmac` provides true cryptographic binding. Other modes are deterministic transformations useful for controlled obfuscation.

---

## 5. HMAC Mode and Native Secret

Diagnostics‑aware dual behavior

| Variant capability             | Behavior                                                  |
| ------------------------------ | --------------------------------------------------------- |
| `extra['supports_secret']=True`  | Pepper key passed natively (e.g., `Argon2(secret=key)`)   |
| `extra['supports_secret']=False` | Pepper applied externally as `HMAC(key, password)`        |

This decision is made automatically by `PepperFactory` based on `hashing.registry.get_diagnostic(variant)`.

HMAC details
- Uses `hashlib` digests (`sha256` default, `sha512`, etc.).
- Produces fixed‑length hex output.
- Warns if key < 8 chars (still allowed).
- Missing key → configuration error (raises).
- Recommended key: ≥ 32 random bytes (ASCII/base64).

---

## 6. Interleave Mode

- `PEPPER_INTERLEAVE_FREQ ≤ 0` → treated as noop (warning logged).
- Cyclically inserts characters from the token every N characters.
- Token comes from `PEPPER_INTERLEAVE_TOKEN` or falls back to `PEPPER_SECRET`.
- Provides only light obfuscation — not cryptographically secure.

---

## 7. Examples

Prefix + Suffix

```bash
export PEPPER_MODE=prefix_suffix
export PEPPER_PREFIX='['
export PEPPER_SUFFIX=']'
# "admin" -> "[admin]"
```

Interleave

```bash
export PEPPER_MODE=interleave
export PEPPER_SECRET='XYZ'
export PEPPER_INTERLEAVE_FREQ=2
# "abcdef" -> "abXcdYefZ"
```

HMAC

```bash
export PEPPER_MODE=hmac
export PEPPER_HMAC_KEY='SuperStrongPepperKey!!!'
export PEPPER_HMAC_ALGO=sha512
# "secret" -> 128 hex chars
```

---

## 8. Integration with the Hashing Façade

Simplified flow

```
Algorithm.hash(password)
  ↓
PepperFactory.from_config(variant, config)
  ↓
if diagnostics.extra['supports_secret'] is True:
    algo_kwargs = {"secret": key_bytes}   # native keyed mode (e.g., Argon2)
else:
    prehash_pipeline = HMAC(...)          # external HMAC prehash
  ↓
implementation.hash_raw(peppered_password)
```

You normally do not call `PepperFactory` yourself. The `Algorithm` façade constructs and applies the pepper plan during initialization.

---

## 9. Diagnostics & Capability Awareness

The pepper factory uses the cached diagnostics snapshot via the hashing registry (late‑bound import):

```python
import securitykit.hashing.registry as reg
diag = reg.get_diagnostic("argon2")
print(diag.available, diag.extra.get("supports_secret"))
```

Typical outcomes
- Argon2 ≥ 21.3.0 → `supports_secret=True` → native secret path.
- Argon2 < 21.3.0 → `supports_secret=False` → HMAC prehash fallback.
- bcrypt, scrypt, Werkzeug PBKDF2 → always external pepper (no native secret concept).

---

## 10. Caching and Lazy Loading

- Strategies are lazily registered and loaded on first use.
- The generic pepper pipeline (`transform/pepper/pipeline.py`) caches built strategies using an LRU keyed by the current `PEPPER_*` snapshot.
- The PepperFactory itself is intentionally lightweight; it is invoked by `Algorithm` construction and returns a small `PepperApplication` object.
- For config rotation in API flows, use your API’s reload entry point (e.g., `securitykit.api.password_security.reload_configuration`) to rebuild singletons that capture pepper settings.

---

## 11. Error Handling and Fallback Behavior

| Scenario                        | Behavior                                      | Origin/Notes                                     |
| ------------------------------- | --------------------------------------------- | ------------------------------------------------ |
| `PEPPER_ENABLED=false`          | Bypass (noop)                                 | Applied in `PepperFactory`                       |
| HMAC key missing                | Configuration error (raises)                  | `PepperFactory` in `hmac` mode                   |
| Unsupported HMAC digest         | Construction error (raises)                   | Strategy builder validates via `hashlib`         |
| Interleave freq ≤ 0             | Degrades to noop (warning)                    | Strategy builder logs a warning                  |
| Unknown mode                    | Configuration error (raises)                  | Strategy builder raises `UnknownPepperStrategy`  |
| Unexpected strategy error       | Pipeline degrades to noop (logged error)      | `transform/pepper/pipeline.py` fallback path     |

Design intent
- In high‑level UI pipelines (via `pipeline.apply_pepper`), failures log and degrade to noop.
- In explicit factory construction (during façade initialization), invalid configuration raises early and loudly so misconfigurations don’t go unnoticed.

---

## 12. Security Guidance

1. Prefer HMAC mode whenever possible.
2. Store pepper keys outside source control (secrets manager).
3. Plan for rotation; versioned keys (e.g., `PEPPER_VERSION`) are on the roadmap.
4. Do not treat obfuscation modes (prefix/suffix/interleave) as cryptographic protection.
5. Monitor logs for unexpected noop or fallback warnings.
6. Consider HKDF‑derived per‑tenant or per‑user keys for stronger isolation.

---

## 13. Extending (Custom Strategy)

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

Enable via:
```
PEPPER_MODE=reverse
```

Guidelines
- Keep transformations pure and stateless.
- Return a new string (no mutation).
- If construction is expensive, consider your own internal cache.

---

## 14. Deployment Checklist

| Item                                  | OK |
| ------------------------------------- | -- |
| Chosen `PEPPER_MODE` documented       | ☐  |
| HMAC key ≥ 32 chars                   | ☐  |
| No legacy `pepper=` code paths        | ☐  |
| Round‑trip hash/verify test passes    | ☐  |
| No unexpected noop/fallback in logs   | ☐  |
| Rotation procedure documented         | ☐  |
| Secrets in secure store (not `.env`)  | ☐  |

---

## 15. Roadmap

| Feature                                  | Benefit                                    |
| ---------------------------------------- | ------------------------------------------ |
| `PEPPER_VERSION` tagging                 | Smooth rotation / dual verification window |
| Per‑user HKDF derivation                 | Reduce blast radius on compromise          |
| Composite pipelines (HMAC + suffix, …)   | Flexible defense‑in‑depth                  |
| CLI validator (`pepper validate`)        | Detect config errors early                 |
| Metrics and counters                     | Operational visibility                     |
| Hardware‑derived secrets                 | Environment‑bound hardening                |

---

Usage recommendation
Always rely on the hashing façade (`Algorithm` or `HashingFactory`) for pepper handling. Direct use of pepper strategies is reserved for advanced tooling or migrations.
