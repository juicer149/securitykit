# SecurityKit Password

The `securitykit.password` package provides **password policy definition** and **runtime validation**.  
It is deliberately decoupled from the hashing subsystem so that password quality is enforced *before* any hashing or benchmarking logic runs.

---

## Contents

1. Goals
2. Components
3. Quick Start
4. Validation Rules
5. Error Semantics
6. Integration With Hashing (`PasswordSecurity`)
7. Recommended Usage Pattern
8. Extending / Custom Policies
9. Testing Guidelines
10. Security Considerations
11. Roadmap

---

## 1. Goals

| Goal                | Description                                                           |
|---------------------|-----------------------------------------------------------------------|
| Explicit Policy     | All requirements defined in a single dataclass                        |
| Deterministic       | No probabilistic scoring; strict boolean criteria                     |
| Fast Feedback       | Fail early before hashing or persistence                              |
| Composable          | Works standalone or via the high-level API (`securitykit.api`)        |
| Observable          | Logs warnings when chosen parameters fall below recommended baselines |

---

## 2. Components

### `PasswordPolicy` (`password/policy.py`)

Dataclass specifying complexity requirements:

| Field             | Type  | Meaning                                                | Typical Default |
|-------------------|-------|--------------------------------------------------------|-----------------|
| `min_length`      | int   | Minimum number of characters                           | 12 (recommended) |
| `require_upper`   | bool  | At least one uppercase A–Z                             | True            |
| `require_lower`   | bool  | At least one lowercase a–z                             | True            |
| `require_digit`   | bool  | At least one digit 0–9                                 | True            |
| `require_special` | bool  | At least one non-alphanumeric symbol                   | True            |

Validation in `__post_init__`:
- Enforces a minimum lower bound (e.g. warns if `min_length` < recommended baseline).
- Ensures values are of expected type (leveraging construction context).

### `PasswordValidator` (`password/validator.py`)

Applies a `PasswordPolicy` to actual password strings.

Method:
```python
validate(password: str) -> None
```
Raises `InvalidPolicyConfig` if any rule is violated.

---

## 3. Quick Start

```python
from securitykit.password import PasswordPolicy, PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig

policy = PasswordPolicy(min_length=12, require_upper=True, require_digit=True)
validator = PasswordValidator(policy)

validator.validate("StrongPass123!")   # OK

try:
    validator.validate("weak")
except InvalidPolicyConfig as e:
    print("Rejected:", e)
```

---

## 4. Validation Rules

Given a policy, a candidate password must:

| Rule                    | Check Performed                                  |
|-------------------------|--------------------------------------------------|
| Length                  | `len(password) >= min_length`                    |
| Uppercase requirement   | Presence of `[A-Z]` if `require_upper`           |
| Lowercase requirement   | Presence of `[a-z]` if `require_lower`           |
| Digit requirement       | Presence of `[0-9]` if `require_digit`           |
| Special requirement     | Presence of at least one char `[^A-Za-z0-9]` if `require_special` |

All failing conditions are accumulated in a single exception message for clarity.

---

## 5. Error Semantics

| Scenario                                   | Behavior / Exception                           |
|--------------------------------------------|------------------------------------------------|
| Policy constructed with weak parameters    | Warning logged (does not raise)                |
| Password violates one or more constraints  | `InvalidPolicyConfig` raised                   |
| Empty password                             | Treated like any violation (length + others)   |
| Non-string input (should not happen)       | Upstream code should ensure string; else failure is explicit |

---

## 6. Integration With Hashing (`PasswordSecurity`)

High-level flow when using `securitykit.api.password_security.PasswordSecurity`:

1. PasswordPolicy is built (from environment or defaults).
2. Input password is validated.
3. Hashing algorithm (e.g. Argon2) produces a digest.
4. On verification, only hashing is performed (policy enforcement is usually skipped for historical stored passwords, but you can re‑validate if desired).
5. Optionally call `rehash_password` if algorithm parameters evolved.

---

## 7. Recommended Usage Pattern

```python
from securitykit.api.password_security import PasswordSecurity

service = PasswordSecurity.from_env()

# Register/login flow
candidate = "NewUserPass#2024"
digest = service.hash(candidate)             # Validates + hashes
assert service.verify(candidate, digest)     # Returns True
```

If you want to validate separately:

```python
validator = service.validator   # underlying PasswordValidator
validator.validate(candidate)   # raises if not acceptable
```

---

## 8. Extending / Custom Policies

If you need additional fields (e.g. disallow whitespace, max length):

```python
from dataclasses import dataclass
from securitykit.password.policy import PasswordPolicy

@dataclass
class ExtendedPasswordPolicy(PasswordPolicy):
    disallow_space: bool = True

    def __post_init__(self):
        super().__post_init__()
        if self.disallow_space and self.min_length < 8:
            # Example extra constraint rule
            pass
```

You can then wrap this in your own service or validator.  
(Current high-level `PasswordSecurity` expects the default `PasswordPolicy`, so integration hooks would be needed for custom classes.)

---

## 9. Testing Guidelines

| Test Type                | What to Cover                                    |
|--------------------------|--------------------------------------------------|
| Positive validation      | Strong password passes all enabled rules         |
| Negative cases           | Individually missing uppercase/digit/special     |
| Aggregated failures      | A password failing multiple rules yields all in message |
| Boundary length          | Exactly `min_length` passes; length − 1 fails     |
| Policy warnings          | Construct with `min_length` below recommended baseline and assert log captured |

Sample pytest snippet:

```python
import pytest
from securitykit.password import PasswordPolicy, PasswordValidator
from securitykit.exceptions import InvalidPolicyConfig

def test_multiple_failures():
    policy = PasswordPolicy(min_length=8, require_upper=True, require_digit=True)
    validator = PasswordValidator(policy)
    with pytest.raises(InvalidPolicyConfig) as exc:
        validator.validate("abc")
    assert "upper" in str(exc.value).lower()
    assert "digit" in str(exc.value).lower()
```

---

## 10. Security Considerations

| Concern                  | Guidance |
|--------------------------|----------|
| Minimum length           | Prefer 12+ (baseline), consider 14+ for higher assurance |
| Composition requirements | Avoid excessive complexity if using passphrases; adapt to UX |
| Reuse detection          | Not handled here; integrate with history service if needed |
| Breach lists             | Not yet integrated (planned Have I Been Pwned support) |
| Rate limiting            | Validator is fast; combine with external throttling on auth endpoints |
| Logging                  | Never log raw passwords; only policy warnings are logged |

---

## 11. Roadmap

| Item                                | Status |
|-------------------------------------|--------|
| Policy presets (e.g. NIST profile)  | Planned |
| Entropy / zxcvbn-style scoring      | Planned |
| Breach (HIBP) integration           | Planned |
| Config-driven optional checks (e.g. forbid whitespace) | Planned |
| International character class support | Planned |

---

## 12. Reference Summary

| Object            | Import Path                                |
|-------------------|--------------------------------------------|
| PasswordPolicy    | `securitykit.password.PasswordPolicy`      |
| PasswordValidator | `securitykit.password.PasswordValidator`   |
| Exception raised  | `securitykit.exceptions.InvalidPolicyConfig` |

---

## 13. Minimal End-to-End Example

```python
from securitykit.api.password_security import PasswordSecurity

service = PasswordSecurity.from_env()
password = "ExamplePass123!"
digest = service.hash(password)

assert service.verify(password, digest) is True
maybe_new_digest = service.rehash_password(password, digest)
# either identical or a new hash if parameters changed
```

---

The password module is intentionally small, focused, and immutable in behavior.  
Complex orchestration (rehash, benchmarking, parameter tuning) lives in other subsystems, keeping policy logic itself simple and predictable.
