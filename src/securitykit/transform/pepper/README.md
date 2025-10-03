# Pepper Subsystem

Centralized secret‑driven transformation applied to a plaintext password **before**
it is passed to any hashing algorithm. Algorithms (Argon2, bcrypt, …) receive an
already “peppered” value; they are not pepper‑aware.

---

## Table of Contents

1. Rationale  
2. Quick Start  
3. Configuration (`PEPPER_*`)  
4. Strategies  
5. HMAC Mode Notes  
6. Interleave Mode Notes  
7. Examples  
8. Integration with Hashing Façade  
9. Caching & Lazy Loading  
10. Error Handling & Fallback Matrix  
11. Security Guidance  
12. Extending (Custom Strategy)  
13. Deployment Checklist  
14. Roadmap  

---

## 1. Rationale

| Goal                  | Effect                                                         |
|-----------------------|----------------------------------------------------------------|
| Single Responsibility | Hash algorithms focus strictly on hashing / verification      |
| Config Driven         | Behavior controlled exclusively by `PEPPER_*` keys            |
| Extensible            | Add a strategy without touching existing code                 |
| Testable              | Deterministic pure strategies; simple unit tests              |
| Security Optionality  | Provide a cryptographic option (HMAC) when required           |
| Central Enforcement   | Façade guarantees exactly one pepper application per request |

---

## 2. Quick Start

```python
import os
from securitykit.transform.pepper import apply_pepper

os.environ["PEPPER_MODE"] = "prefix_suffix"
os.environ["PEPPER_PREFIX"] = "pre$"
os.environ["PEPPER_SUFFIX"] = "$suf"

pw = "CorrectHorseBatteryStaple!"
peppered = apply_pepper(pw, os.environ)
# "pre$CorrectHorseBatteryStaple!$suf"
```

Normally you do NOT call `apply_pepper` manually—`Algorithm.hash()` / `Algorithm.verify()`
invoke it internally.

---

## 3. Configuration (`PEPPER_*`)

| Variable                | Type (parsed) | Default  | Description                                                         |
|-------------------------|---------------|----------|---------------------------------------------------------------------|
| `PEPPER_ENABLED`        | bool          | `true`   | Master switch                                                       |
| `PEPPER_MODE`           | str           | `noop`   | `noop|prefix|suffix|prefix_suffix|interleave|hmac`                  |
| `PEPPER_SECRET`         | str           | `""`     | Base secret fallback for simple modes                               |
| `PEPPER_PREFIX`         | str           | `""`     | Override prefix (prefix/prefix_suffix modes)                        |
| `PEPPER_SUFFIX`         | str           | `""`     | Override suffix (suffix/prefix_suffix modes)                        |
| `PEPPER_INTERLEAVE_FREQ`| int           | `0`      | Insert token every N chars (≤0 ⇒ noop)                              |
| `PEPPER_INTERLEAVE_TOKEN`| str          | `""`     | Token sequence (fallback: `PEPPER_SECRET`)                          |
| `PEPPER_HMAC_KEY`       | str           | `""`     | Required for `hmac` mode                                            |
| `PEPPER_HMAC_ALGO`      | str           | `sha256` | Hash algorithm (must exist in `hashlib`)                            |

Precedence (simple modes): explicit prefix/suffix > `PEPPER_SECRET`.

---

## 4. Strategies

| Mode            | Transformation                          | Strength Category        |
|-----------------|-----------------------------------------|--------------------------|
| `noop`          | identity                                | –                        |
| `prefix`        | `prefix + password`                     | Obfuscation only         |
| `suffix`        | `password + suffix`                     | Obfuscation only         |
| `prefix_suffix` | `prefix + password + suffix`            | Obfuscation only         |
| `interleave`    | Inserts token every N chars             | Weak obfuscation         |
| `hmac`          | `hex(HMAC(key, password))`              | Cryptographic (strong)   |

> Only `hmac` provides *cryptographic* transformation. Others are deterministic
string decorations (treat them like structured peppering; they do not replace strong hash parameters).

---

## 5. HMAC Mode Notes

- Uses the selected digest algorithm (default `sha256`)
- Result is a fixed‑length hex digest (e.g. 64 chars for sha256)
- Key length warning if `< 8` chars (still allowed, but discouraged)
- Unsupported algorithm raises at build time (`PepperStrategyConstructionError`)
- Recommended key: ≥ 32 random bytes (ASCII or Base64)

---

## 6. Interleave Mode Notes

- `PEPPER_INTERLEAVE_FREQ` ≤ 0 ⇒ treated as noop (warning logged)
- Iteratively inserts one character from token sequence at each step (wraps/cycles)
- Token falls back to `PEPPER_INTERLEAVE_TOKEN` or `PEPPER_SECRET`
- Provides light obfuscation only (NOT cryptographic)

---

## 7. Examples

### Prefix + Suffix via Single Secret

```bash
export PEPPER_MODE=prefix_suffix
export PEPPER_SECRET='SrvPep'
# "pass" -> "SrvPeppassSrvPep"
```

### Explicit Prefix / Suffix

```bash
export PEPPER_MODE=prefix_suffix
export PEPPER_PREFIX='^'
export PEPPER_SUFFIX='$'
# "password" -> "^password$"
```

### Interleave

```bash
export PEPPER_MODE=interleave
export PEPPER_SECRET='XYZ'
export PEPPER_INTERLEAVE_FREQ=2
# "abcdef" -> "abXcdYefZ" (cycles token)
```

### HMAC

```bash
export PEPPER_MODE=hmac
export PEPPER_HMAC_KEY='SuperStrongPepperKey!!!'
export PEPPER_HMAC_ALGO=sha256
# "secret" -> 64 hex chars
```

---

## 8. Integration with Hashing Façade

Simplified flow:

```
Algorithm.hash(password)
  ↓
apply_pepper(password, config)      # chooses / caches strategy
  ↓
implementation.hash_raw(peppered)
```

You can pass any mapping with `PEPPER_*` keys (not limited to `os.environ`).

---

## 9. Caching & Lazy Loading

- Strategy build is cached using a snapshot (sorted tuple of relevant `PEPPER_*` pairs)
- If keys change → build invoked again (new cache entry)
- Strategy registry supports lazy import: if the internal registry is empty at first lookup, it auto‑imports strategies
- For runtime rotation (e.g. key rotation) you may expose an explicit `invalidate_pepper_cache()` (not provided by default)

---

## 10. Error Handling & Fallback Matrix

| Scenario                         | Behavior / Result        | Logged |
|---------------------------------|--------------------------|--------|
| Unknown `PEPPER_MODE`           | Fallback to `noop`       | Error  |
| Disabled (`PEPPER_ENABLED=false`)| Uses `noop`             | Debug  |
| HMAC without key                | Config error → noop      | Error  |
| Unsupported HMAC digest         | Construction error → noop| Error  |
| Short HMAC key (<8)             | Still used               | Warn   |
| Interleave freq ≤ 0             | Treated as noop          | Warn   |

> Fallback design prevents hard authentication failure due to misconfiguration but you **must** monitor logs for silent regressions (e.g. unintended noop).

---

## 11. Security Guidance

1. Prefer **HMAC** mode for genuine cryptographic binding.
2. Keep HMAC keys outside version control (secret manager recommended).
3. Plan for future rotation (anticipated: `PEPPER_VERSION`).
4. Do not treat obfuscation modes (prefix/suffix/interleave) as a substitute for strong hashing parameters.
5. Monitor logs for fallback warnings—unexpected `noop` may indicate an incident.
6. Consider deriving per‑tenant or per‑user keys with HKDF (on roadmap).

---

## 12. Extending (Custom Strategy)

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

Usage: `PEPPER_MODE=reverse`

Guidelines:
- Keep strategies pure
- Avoid raising unless truly unrecoverable
- If expensive to construct, consider internal lightweight caching

---

## 13. Deployment Checklist

| Item                                      | OK |
|-------------------------------------------|----|
| Chosen `PEPPER_MODE` documented           |    |
| HMAC key length ≥ 32 chars                |    |
| No legacy `pepper=` arguments anywhere    |    |
| Roundtrip test (hash → verify) passes     |    |
| Logs free of unexpected fallback errors   |    |
| Rotation plan (if HMAC) documented        |    |
| Secrets stored in manager (not `.env`)    |    |

---

## 14. Roadmap

| Idea                               | Benefit                                      |
|------------------------------------|----------------------------------------------|
| `PEPPER_VERSION` tagging           | Graceful rotation / dual verify window       |
| HKDF per user (user_id + master)   | Minimize blast radius on partial compromise  |
| Composite strategy pipelines       | Chain transformations (e.g. HMAC + prefix)   |
| Validation CLI (`pepper validate`) | Early detection of misconfiguration          |
| Fallback metrics / counters        | Operational visibility                        |
| Key derivation from hardware ID    | Env‑specific hardening                        |

---

**Use through the hashing façade** unless building
deployment/maintenance tooling (e.g. rotation scripts or custom strategies).
