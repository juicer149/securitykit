# SecurityKit

A modular and extensible **password security toolkit** for Python.  
It provides consistent APIs for **password hashing**, **global pepper support**, and **password policy enforcement**, with configuration via `.env` or dicts.

---

## Features

* **Algorithms**
  * Argon2id password hashing (`argon2-cffi`)
  * Pluggable registry (`AlgorithmRegistry`) for adding new algorithms
  * `Algorithm` abstraction provides a uniform API (`hash`, `verify`, `needs_rehash`, `__call__`)
  * Optional **global pepper support** → applied consistently across all algorithms

* **Policies**
  * `Argon2Policy`: configure Argon2id parameters (time, memory, parallelism, hash length, salt)
    * Enforces OWASP-based minimums
    * Logs warnings if parameters are below recommended baselines
  * `PasswordPolicy`: enforce password complexity rules (length, upper/lower/digit/special)
    * Defaults are intentionally lenient (min length = 8), but warnings are logged if below OWASP recommendations
  * **Standalone:** `PasswordPolicy` is not part of the `PolicyRegistry` (unlike Argon2)
    * Always available, no explicit toggle required
    * Designed for app-level checks (e.g. during registration/reset)

* **Factory**
  * `SecurityFactory`: builds algorithms + policies from a simple config dict
  * `.env` support → `HASH_VARIANT=argon2` loads Argon2 policy
  * `.env` support → global pepper (`PEPPER_VALUE`)
  * `.env` support → password policy (`PASSWORD_MIN_LENGTH`, etc.)

* **Extensibility**
  * Add new algorithms with `@register_algorithm("bcrypt")`
  * Add new policies with `@register_policy("argon2")`, etc.
  * Password policy stays standalone → lightweight, explicit, not tied to hashing backend

---

## Installation

```bash
# clone and enter project
git clone https://github.com/yourname/securitykit.git
cd securitykit

# create venv and install in editable mode with dev tools
make install
````

Requires **Python 3.10+**.

---

## Usage

### 1. Hashing with Argon2

```python
from securitykit import Algorithm, Argon2Policy

policy = Argon2Policy(time_cost=6, memory_cost=131072, parallelism=4)
argon2 = Algorithm("argon2", policy, pepper="supersecretpepper")

hashed = argon2.hash("MySecretPass!")
print(argon2.verify("MySecretPass!", hashed))  # True
print(argon2.verify("WrongPass", hashed))      # False

# Rehash check
if argon2.needs_rehash(hashed):
    print("Password should be rehashed with updated parameters")
```

### 2. Enforcing Password Policy

```python
from securitykit import PasswordPolicy, InvalidPolicyConfig

policy = PasswordPolicy(min_length=12)
policy.validate("StrongPass123!")  # OK
policy.validate("short")           # raises InvalidPolicyConfig
```

### 3. Using the SecurityFactory with `.env`

`.env`:

```env
HASH_VARIANT=argon2
ARGON2_TIME_COST=6
ARGON2_MEMORY_COST=131072
ARGON2_PARALLELISM=4
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16

# Global pepper (applies to all algorithms)
PEPPER_VALUE=supersecretpepper

# Password policy
PASSWORD_MIN_LENGTH=12
PASSWORD_REQUIRE_UPPER=true
PASSWORD_REQUIRE_LOWER=true
PASSWORD_REQUIRE_DIGIT=true
PASSWORD_REQUIRE_SPECIAL=true
```

Code:

```python
import os
from dotenv import load_dotenv
from securitykit import SecurityFactory

load_dotenv()
config = dict(os.environ)

factory = SecurityFactory(config)

# Algorithm (Argon2 with pepper)
hasher = factory.get_algorithm()
hash = hasher.hash("AnotherPass!")
print(hasher.verify("AnotherPass!", hash))

# Password policy
policy = factory.get_password_policy()
policy.validate("AnotherPass!")

# Rehash flow
if hasher.needs_rehash(hash):
    new_hash = hasher.hash("AnotherPass!")
    print("Password rehashed:", new_hash)
```

---

## Running Tests

```bash
make test
```

---

## Roadmap

* [ ] Add more algorithms (Bcrypt, PBKDF2, Scrypt)
* [ ] Benchmark utility to auto-tune defaults for your hardware
* [ ] Integration helpers for Flask / FastAPI
* [ ] Password rehashing helpers (`rehash(password, old_hash)`)
* [ ] Key derivation utilities for symmetric crypto

---

## License

MIT License – see [LICENSE](./LICENSE).
