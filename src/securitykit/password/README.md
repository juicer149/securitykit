# SecurityKit Password

The `securitykit.password` package provides a complete, deterministic password policy framework — defining, evaluating, and enforcing password strength and compliance rules before any hashing occurs. It is deliberately isolated from the hashing subsystem so that password quality and UX feedback are handled predictably, with zero dependency on algorithm availability.

---

## Contents

1. Goals
2. Components
3. Quick Start
4. Validation Rules
5. Complexity Scoring Model
6. Error & Exception Semantics
7. Integration with Hashing
8. Recommended Usage Pattern
9. Extending / Custom Policies
10. Testing Guidelines
11. Security Considerations
12. Roadmap
13. Reference Summary
14. End-to-End Example

---

## 1. Goals

| Goal                | Description                                                                    |
| ------------------- | ------------------------------------------------------------------------------ |
| Explicit Policy     | All password requirements defined in one dataclass (`PasswordPolicy`).         |
| Deterministic       | Strict boolean logic; no probabilistic “entropy” guesses.                      |
| Fast Feedback       | Reject invalid passwords early — before hashing or persistence.                |
| Composable          | Works standalone or integrated via the `securitykit.api` façade.               |
| Observable          | Logs structured feedback and metrics (never the password).                     |
| Configurable        | Fully environment-driven via `PASSWORD_*` keys or mapping input.               |
| Low Overhead        | Lightweight checks for pre-hashing validation in real-time UX or API contexts. |

---

## 2. Components

### `PasswordPolicy` (`password/policy.py`)

Defines all enforcement parameters and complexity thresholds as a single dataclass.

| Field                   | Type | Description                                     | Default |
| ----------------------- | ---- | ----------------------------------------------- | ------- |
| `min_length`            | int  | Hard minimum number of characters               | 8       |
| `require_upper`         | bool | Require at least one A–Z                        | True    |
| `require_lower`         | bool | Require at least one a–z                        | True    |
| `require_digit`         | bool | Require at least one 0–9                        | True    |
| `require_special`       | bool | Require at least one non-alphanumeric           | True    |
| `complexity_rule`       | int  | Minimum number of fulfilled rules (1–5)         | 3       |
| `complexity_min_length` | int  | Minimum length contributing to complexity score | 12      |

Validation
- Enforces numeric and logical bounds (`__post_init__`).
- Logs warnings when configured too weak (< recommended) or unusually high.
- Soft complexity rules are validated separately; redundant configurations are logged.

Defaults and bounds: `securitykit.password.defaults`.

---

### `PasswordStrengthEvaluator` (`password/strength_evaluator.py`)

Rule-based, deterministic complexity evaluation.

Features
- Computes a 5-bit mask representing fulfilled rules:
  - min_length (soft: based on `complexity_min_length`)
  - uppercase
  - lowercase
  - digit
  - special
- Returns structured feedback such as:

```python
{
    "strength": "Strong",
    "fulfilled_rules": 4,
    "missing": ["special"],
    "mask": 0b11110
}
```

Strength mapping
| Fulfilled | Strength Label   |
| --------- | ---------------- |
| 0         | Extremely Weak   |
| 1         | Very Weak        |
| 2         | Weak             |
| 3         | Moderate         |
| 4         | Strong           |
| 5         | Very Strong      |

Helpers: `count_fulfilled(mask)`, `describe_strength(fulfilled)`, `describe_missing(mask)`.

---

### `PasswordValidator` (`password/validator.py`)

Enforces a `PasswordPolicy` using both hard and soft complexity rules.

Behavior
1. Checks hard bounds (length, required character classes).
2. Computes complexity bitmask without noisy logging.
3. Raises `PasswordValidationError` with clear messages.
4. Provides conveniences:
   - `strength_label(password)`
   - `feedback(password)` (for UX)

Example feedback

```python
{
  "strength": "Moderate",
  "message": "Password strength: Moderate (3/5 rules satisfied, missing: special, digit)",
  "missing": "special, digit"
}
```

---

### `PasswordGate` (`password/gate.py`)

Fast, boolean-only gate for pre-authentication screening.

- Designed for registration/change flows (and optionally verify flows) where you need a quick allow/deny before hashing.
- No exceptions — just a boolean decision and optional structured reasons.

Methods
- `allow(password: str) -> bool`
- `reject_reason(password: str) -> dict`
- `quick_strength(password: str) -> str`
- `log_decision(password: str) -> None`

Example

```python
from securitykit.password.gate import PasswordGate, PasswordPolicy

policy = PasswordPolicy(min_length=12, complexity_rule=3)
gate = PasswordGate(policy)

if not gate.allow(password):
    return {"error": "Invalid password"}
```

Important semantics
- Hard length is enforced against `policy.min_length` (numeric check).
- The “length” bit in the complexity mask is soft: it only turns on when `len(password) >= complexity_min_length` and contributes to the `complexity_rule` count. It is not required by the gate as a hard feature.

---

### `PasswordFactory` (`password/factory.py`)

Builds `PasswordPolicy` and `PasswordValidator` from an environment or a dict.

```python
from securitykit.password.factory import PasswordFactory

config = {
    "PASSWORD_MIN_LENGTH": "12",
    "PASSWORD_COMPLEXITY_RULE": "3",
}

factory = PasswordFactory(config)
validator = factory.get_validator()
validator.validate("StrongPass1!")
```

Note: The config loader is strict about types; for booleans use `true/false`, not `1/0`.

---

## 3. Quick Start

```python
from securitykit.password import PasswordPolicy, PasswordValidator
from securitykit.exceptions import PasswordValidationError

policy = PasswordPolicy(min_length=10, complexity_rule=3)
validator = PasswordValidator(policy)

validator.validate("StrongPass123!")  # passes

try:
    validator.validate("weak")
except PasswordValidationError as e:
    print("Rejected:", e)
```

---

## 4. Validation Rules

| Rule       | Check                                        |
| ---------- | -------------------------------------------- |
| Length     | `len(password) >= min_length`                |
| Uppercase  | `[A-Z]` required if `require_upper`          |
| Lowercase  | `[a-z]` required if `require_lower`          |
| Digit      | `[0-9]` required if `require_digit`          |
| Special    | `[^A-Za-z0-9]` required if `require_special` |
| Complexity | ≥ `complexity_rule` of 5 bits must be set    |

Note: The complexity rule is soft but enforced deterministically.

---

## 5. Complexity Scoring Model

Each password is scored across five independent binary rules. The evaluator constructs a bitmask (5 bits) and counts the number of fulfilled rules:

1. Minimum length (≥ `complexity_min_length`) — soft
2. Uppercase letter
3. Lowercase letter
4. Digit
5. Special character

The total count maps to the strength label (“Weak”, “Strong”, etc.).

Example log:
```
[INFO] securitykit.password: Password evaluated: strength=Strong, fulfilled=4/5, missing=['special']
```

---

## 6. Error & Exception Semantics

| Scenario                    | Behavior                                           |
| --------------------------- | -------------------------------------------------- |
| Too short or too long       | Raises `PasswordValidationError`                   |
| Missing required class      | Raises `PasswordValidationError`                   |
| Insufficient complexity     | Raises `PasswordValidationError` with missing list |
| Weak configuration (policy) | Logs warning                                       |
| Empty password              | Always fails                                       |

All exceptions are explicit — no silent fallback.

---

## 7. Integration with Hashing

Hashing APIs validate before hashing and support optional gating on verify.

```python
import securitykit.api as sk

digest = sk.hash_password("Example#Pass123")
assert sk.verify_password("Example#Pass123", digest)
maybe_new = sk.rehash_password("Example#Pass123", digest)
```

Details
- `hash_password`: Applies `PasswordGate` (fast precheck) and `PasswordValidator` before hashing.
- `verify_password`: By default does not apply the gate to avoid blocking legitimate logins for existing weak/legacy passwords. You can enable gating on verify by setting `PASSWORD_GATE_ON_VERIFY=true` in your configuration.

---

## 8. Recommended Usage Pattern

```python
from securitykit.password.factory import PasswordFactory

env = {
    "PASSWORD_MIN_LENGTH": "12",
    "PASSWORD_COMPLEXITY_RULE": "3",
}

validator = PasswordFactory(env).get_validator()
validator.validate("StrongPass1!")
```

UX feedback:

```python
feedback = validator.feedback("StrongPass1!")
print(feedback["message"])
# → "Password strength: Strong (4/5 rules satisfied, missing: none)"
```

---

## 9. Extending / Custom Policies

Subclass `PasswordPolicy` to add constraints.

```python
from dataclasses import dataclass
from securitykit.password.policy import PasswordPolicy
from securitykit.logging_config import logger

@dataclass
class ExtendedPasswordPolicy(PasswordPolicy):
    disallow_whitespace: bool = True

    def __post_init__(self):
        super().__post_init__()
        if self.disallow_whitespace:
            logger.debug("Whitespace disallowed in passwords.")
```

---

## 10. Testing Guidelines

| Test Type  | Purpose                                              |
| ---------- | ---------------------------------------------------- |
| Positive   | Confirm strong passwords pass                        |
| Negative   | Ensure missing uppercase/digit/special cause failure |
| Boundary   | Check edge cases around min/max lengths              |
| Complexity | Verify bitmask logic and strength label              |
| Gate       | Verify `PasswordGate.allow()` boolean accuracy       |
| Factory    | Ensure env-based config builds valid policy          |
| API Gate   | Toggle `PASSWORD_GATE_ON_VERIFY` and assert behavior |

---

## 11. Security Considerations

| Concern           | Recommendation                                    |
| ----------------- | ------------------------------------------------- |
| Minimum Length    | ≥ 12 (≥ 14 for sensitive contexts)                |
| Config Validation | Do not suppress policy warnings                   |
| Usability         | Tune `complexity_rule` instead of all `require_*` |
| Breach Detection  | Future: integrate with HaveIBeenPwned API         |
| Logging           | Never log plaintext passwords                     |
| UX                | Strength labels are safe to expose to users       |

---

## 12. Roadmap

| Feature                        | Status  |
| ------------------------------ | ------- |
| Bitmask complexity engine      | ✅ Done  |
| PasswordGate boolean pre-check | ✅ Done  |
| Environment-driven factory     | ✅ Done  |
| HIBP breach integration        | 🔜 Planned |
| zxcvbn entropy scoring         | 🔜 Planned |
| NIST/OWASP preset profiles     | 🔜 Planned |
| Adaptive feedback for UX       | 🔜 Planned |

---

## 13. Reference Summary

| Object                    | Path                                                                |
| ------------------------- | ------------------------------------------------------------------- |
| PasswordPolicy            | `securitykit.password.policy.PasswordPolicy`                        |
| PasswordValidator         | `securitykit.password.validator.PasswordValidator`                  |
| PasswordGate              | `securitykit.password.gate.PasswordGate`                            |
| PasswordFactory           | `securitykit.password.factory.PasswordFactory`                      |
| PasswordStrengthEvaluator | `securitykit.password.strength_evaluator.PasswordStrengthEvaluator` |
| Defaults                  | `securitykit.password.defaults`                                     |
| Config Prefix             | `securitykit.config.PASSWORD_ENV_PREFIX`                            |
| Exception                 | `securitykit.exceptions.PasswordValidationError`                    |

---

## 14. End-to-End Example

```python
import securitykit.api as sk

password = "ExamplePass123!"
digest = sk.hash_password(password)

assert sk.verify_password(password, digest)
maybe_new = sk.rehash_password(password, digest)
```

The password subsystem is small, declarative, and independent. Its purpose is to define what constitutes an acceptable password, provide measurable feedback, and fail fast — before hashing or authentication logic runs.
