# SecurityKit Password

The `securitykit.password` package provides **password policy definition**, **complexity evaluation**, and **runtime validation**.
It is deliberately decoupled from the hashing subsystem so that password quality is enforced *before* any hashing or benchmarking logic runs.

---

## Contents

1. Goals
2. Components
3. Quick Start
4. Validation Rules
5. Password Complexity Scoring
6. Error Semantics
7. Integration With Hashing
8. Recommended Usage Pattern
9. Extending / Custom Policies
10. Testing Guidelines
11. Security Considerations
12. Roadmap
13. Reference Summary
14. Minimal End-to-End Example

---

## 1. Goals

| Goal            | Description                                                    |
| --------------- | -------------------------------------------------------------- |
| Explicit Policy | All requirements defined in a single dataclass                 |
| Deterministic   | No probabilistic scoring; strict boolean + bitmask criteria    |
| Fast Feedback   | Fail early before hashing or persistence                       |
| Composable      | Works standalone or via the high-level API (`securitykit.api`) |
| Observable      | Logs warnings and strength info (never logs the password)      |
| Configurable    | Fully environment-driven via `.env` or injected config         |

---

## 2. Components

### `PasswordPolicy` (`password/policy.py`)

Dataclass defining both **hard enforcement** and **soft complexity thresholds**.

| Field                   | Type | Description                                       | Default |
| ----------------------- | ---- | ------------------------------------------------- | ------- |
| `min_length`            | int  | Hard minimum number of characters                 | 12      |
| `require_upper`         | bool | Must contain at least one uppercase A–Z           | True    |
| `require_lower`         | bool | Must contain at least one lowercase a–z           | True    |
| `require_digit`         | bool | Must contain at least one digit 0–9               | True    |
| `require_special`       | bool | Must contain at least one non-alphanumeric symbol | True    |
| `complexity_rule`       | int  | Minimum number of fulfilled rules (1–5)           | 3       |
| `complexity_min_length` | int  | Soft rule contributing to complexity score        | 12      |

Validation in `__post_init__`:

* Enforces numeric bounds and logs warnings if configuration is weak or excessive.
* Validates that `complexity_rule` and `complexity_min_length` are within safe limits.

All default constants are centralized in `securitykit.password.defaults`.

---

### `PasswordStrengthEvaluator` (`password/strength_evaluator.py`)

Evaluates password strength and produces both a **bitmask** and human-readable feedback.

**Features:**

* Modular rules (`check_length_rule`, `check_regex_rules`)
* Returns a structured dict:

```python
{
    "strength": "Strong",
    "fulfilled_rules": 4,
    "missing": ["special"],
    "mask": 0b11110,
}
```

* Provides helpers:
  * `count_fulfilled(mask)`
  * `describe_strength(fulfilled)`
  * `describe_missing(mask)`

| Fulfilled | Strength Level |
| --------- | -------------- |
| 0         | Extremely Weak |
| 1         | Very Weak      |
| 2         | Weak           |
| 3         | Moderate       |
| 4         | Strong         |
| 5         | Very Strong    |

---

### `PasswordValidator` (`password/validator.py`)

Applies the policy and evaluator together.

Performs:

1. Hard checks (min/max length and required character classes)
2. Soft check (complexity bitmask threshold)
3. Raises `InvalidPolicyConfig` when violations occur

Performs a runtime type check and raises `TypeError` if `policy` is not a `PasswordPolicy`.

Provides UX-friendly helpers:

* `strength_label(password)`
* `feedback(password)` → returns structured messages for UI frameworks (e.g. Flask-WTF).

---

### `PasswordFactory` (`password/factory.py`)

Builds `PasswordPolicy` and `PasswordValidator` from configuration, typically using
the prefix defined in `securitykit.config.PASSWORD_ENV_PREFIX` (`"PASSWORD_"`).

```python
from securitykit.password.factory import PasswordFactory

factory = PasswordFactory(config)
policy = factory.get_policy()
validator = factory.get_validator()
```

---

## 3. Quick Start

```python
from securitykit.password import PasswordPolicy, PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig

policy = PasswordPolicy(min_length=10, complexity_rule=3)
validator = PasswordValidator(policy)

validator.validate("StrongPass123!")   # OK

try:
    validator.validate("weak")
except InvalidPolicyConfig as e:
    print("Rejected:", e)
```

---

## 4. Validation Rules

| Rule       | Check                                                |
| ---------- | ---------------------------------------------------- |
| Length     | `len(password) >= min_length`                        |
| Uppercase  | `[A-Z]` present if `require_upper`                   |
| Lowercase  | `[a-z]` present if `require_lower`                   |
| Digit      | `[0-9]` present if `require_digit`                   |
| Special    | `[^A-Za-z0-9]` present if `require_special`          |
| Complexity | At least `complexity_rule` of 5 conditions must pass |

The complexity threshold is soft but logged and enforced consistently.

---

## 5. Password Complexity Scoring

SecurityKit computes a 5-bit complexity score:

1. Evaluate five signals:
   * Minimum length (`complexity_min_length`)
   * Uppercase
   * Lowercase
   * Digit
   * Special character
2. Each fulfilled rule sets a bit in a mask.
3. Fulfilled bit count → strength level (0–5).
4. `PASSWORD_COMPLEXITY_RULE` defines minimum acceptable score.

Example log:

```
[INFO] securitykit: Password evaluated: strength=STRONG, fulfilled=4/5, missing=['special']
```

This output can be reused in real-time UX feedback (e.g. front-end validation).

---

## 6. Error Semantics

| Scenario                  | Behavior                                |
| ------------------------- | --------------------------------------- |
| Weak configuration        | Warning only                            |
| Missing required class    | `InvalidPolicyConfig`                   |
| Insufficient complexity   | `InvalidPolicyConfig` with missing list |
| Empty / too long password | `InvalidPolicyConfig`                   |

---

## 7. Integration With Hashing

Use via high-level API (`securitykit.api`):

```python
import securitykit.api as sk

digest = sk.hash_password("Example#Pass123")
assert sk.verify_password("Example#Pass123", digest)
maybe_new = sk.rehash_password("Example#Pass123", digest)
```

Password policy enforcement happens *before* hashing to fail fast.

---

## 8. Recommended Usage Pattern

```python
from securitykit.password.factory import PasswordFactory

env = {"PASSWORD_MIN_LENGTH": "12", "PASSWORD_COMPLEXITY_RULE": "3"}
validator = PasswordFactory(env).get_validator()
validator.validate("StrongPass1!")
```

For UI feedback:

```python
feedback = validator.feedback("StrongPass1!")
print(feedback["message"])
```

---

## 9. Extending / Custom Policies

```python
from dataclasses import dataclass
from securitykit.password.policy import PasswordPolicy

@dataclass
class ExtendedPasswordPolicy(PasswordPolicy):
    disallow_whitespace: bool = True

    def __post_init__(self):
        super().__post_init__()
        if self.disallow_whitespace:
            # Example custom constraint
            pass
```

---

## 10. Testing Guidelines

| Test       | Purpose                                               |
| ---------- | ----------------------------------------------------- |
| Positive   | Verify strong passwords pass                          |
| Negative   | Missing uppercase/digit/special fails                 |
| Aggregate  | Complexity failures include missing list              |
| Boundary   | Length at `min_length` passes, `min_length - 1` fails |
| Complexity | Confirm bitmask count and strength label              |

---

## 11. Security Considerations

| Concern          | Recommendation                                         |
| ---------------- | ------------------------------------------------------ |
| Minimum length   | Prefer ≥ 12 chars; ≥ 14 for sensitive contexts         |
| Usability        | Tune `complexity_rule` instead of forcing all booleans |
| Breach detection | Integrate with HIBP when available                     |
| Logging          | Never log passwords; only strength summaries           |
| Front-end UX     | Safe to expose evaluator outputs                       |

---

## 12. Roadmap

| Feature                  | Status     |
| ------------------------ | ---------- |
| Bitmask-based evaluation | ✅ Done     |
| Configurable thresholds  | ✅ Done     |
| Live UX feedback         | ✅ Done     |
| HIBP breach detection    | 🔜 Planned |
| Entropy scoring (zxcvbn) | 🔜 Planned |
| NIST/OWASP presets       | 🔜 Planned |

---

## 13. Reference Summary

| Object                    | Path                                                                |
| ------------------------- | ------------------------------------------------------------------- |
| PasswordPolicy            | `securitykit.password.policy.PasswordPolicy`                        |
| PasswordValidator         | `securitykit.password.validator.PasswordValidator`                  |
| PasswordFactory           | `securitykit.password.factory.PasswordFactory`                      |
| PasswordStrengthEvaluator | `securitykit.password.strength_evaluator.PasswordStrengthEvaluator` |
| Exception                 | `securitykit.exceptions.InvalidPolicyConfig`                        |
| Defaults                  | `securitykit.password.defaults`                                     |
| Config prefix             | `securitykit.config.PASSWORD_ENV_PREFIX`                            |

---

## 14. Minimal End-to-End Example

```python
import securitykit.api as sk

password = "ExamplePass123!"
digest = sk.hash_password(password)

assert sk.verify_password(password, digest)
maybe_new_digest = sk.rehash_password(password, digest)
```

The password subsystem is intentionally small, declarative, and self-contained.
Hashing, benchmarking, and rotation logic live elsewhere — this module’s sole purpose
is to define what makes a password acceptable and to make that observable, testable, and configurable.
