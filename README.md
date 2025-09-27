# SecurityKit

A modular and extensible **password security toolkit** for Python.
It provides consistent APIs for **password hashing** and **policy enforcement**,
with support for multiple algorithms and configuration via `.env` or dicts.

---

## Features

* **Algorithms**

  * Argon2id password hashing (`argon2-cffi`)
  * Pluggable registry (`AlgorithmRegistry`) for adding new algorithms
  * `Algorithm` abstraction provides a uniform API (`hash`, `verify`, `__call__`)

* **Policies**

  * `PasswordPolicy`: enforce password complexity rules (length, upper/lower/digit/special)
  * `Argon2Policy`: configure Argon2id parameters (time, memory, parallelism, hash length, salt, pepper)
  * `PolicyRegistry`: dynamic lookup and extensibility
  * Strong validation with `InvalidPolicyConfig` exceptions and warnings

* **Factory**

  * `SecurityFactory`: builds algorithms + policies from a simple config dict
  * `.env` support → `HASH_VARIANT=argon2` auto-loads matching policy values

* **Extensibility**

  * Add new algorithms with `@register_algorithm("bcrypt")`
  * Add new policies with `@register_policy("bcrypt")`
  * Designed for integration in web frameworks (Flask, FastAPI) and standalone use

---

## Installation

```bash
# clone and enter project
git clone https://github.com/yourname/securitykit.git
cd securitykit

# create venv and install in editable mode with dev tools
make install
```

Requires **Python 3.10+**.

---

## Usage

### 1. Hashing with Argon2

```python
from securitykit import Algorithm, Argon2Policy

policy = Argon2Policy(time_cost=6, memory_cost=131072, parallelism=4)
argon2 = Algorithm("argon2", policy)

hashed = argon2.hash("MySecretPass!")
print(argon2.verify(hashed, "MySecretPass!"))  # True
print(argon2.verify(hashed, "WrongPass"))      # False
```

### 2. Enforcing Password Policy

```python
from securitykit import PasswordPolicy, InvalidPolicyConfig

policy = PasswordPolicy(min_length=12)
policy.validate("StrongPass123!")  # OK
policy.validate("short")           # raises InvalidPolicyConfig
```

### 3. Using the SecurityFactory with .env

`.env`:

```env
HASH_VARIANT=argon2
ARGON2_TIME_COST=6
ARGON2_MEMORY_COST=131072
ARGON2_PARALLELISM=4
ARGON2_HASH_LENGTH=32
ARGON2_SALT_LENGTH=16
ARGON2_PEPPER=supersecretpepper
```

Code:

```python
import os
from dotenv import load_dotenv
from securitykit import SecurityFactory

load_dotenv()
config = dict(os.environ)

factory = SecurityFactory(config)
hasher = factory.get_algorithm()

hash = hasher.hash("AnotherPass!")
print(hasher.verify(hash, "AnotherPass!"))
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
* [ ] Password rehashing service (`rehash.py`)

---

## License

MIT License – see [LICENSE](./LICENSE).

