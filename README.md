# SecurityKit

[![Tests](https://github.com/juicer149/securitykit/actions/workflows/ci.yml/badge.svg)](https://github.com/juicer149/securitykit/actions/workflows/ci.yml)

Password hashing for Python applications behind one small API: pick an
algorithm through configuration, add a pepper, and upgrade old hashes
when users log in.

Supports Argon2, bcrypt, scrypt and PBKDF2-SHA256 (via Werkzeug). The
active algorithm and its parameters come from environment variables or
a mapping, so you can raise the cost or switch algorithm without code
changes, and existing hashes keep verifying.

> **Status:** personal project, not audited. See [SECURITY.md](SECURITY.md).

## Features

- One façade over four algorithms, selected with `HASH_VARIANT`
- `needs_rehash` and login-time upgrade, including migration between algorithms
- Pepper as an HMAC prehash, with legacy decoration modes that log a warning
- Fail-closed configuration: an invalid or incomplete pepper setting raises
  instead of silently hashing without it
- Defaults at OWASP levels (Argon2id 64 MiB/t=2, scrypt N=2^17, PBKDF2 600,000,
  bcrypt 12 rounds), with warnings below them
- Benchmark that measures the host and suggests parameters for a target time
- Password policy, validator and a fast pre-check gate
- 125+ tests, 85% coverage, CI on Python 3.10–3.12

## Installation

```bash
pip install "securitykit[alg_argon2] @ git+https://github.com/juicer149/securitykit"
```

The core has no algorithm dependencies. scrypt uses `hashlib` and always
works. The others are extras:

| Extra          | Adds                              |
|----------------|-----------------------------------|
| `alg_argon2`   | argon2-cffi                       |
| `alg_bcrypt`   | bcrypt                            |
| `alg_werkzeug` | Werkzeug (PBKDF2)                 |
| `bench`        | click, tqdm, rich (benchmark CLI) |
| `dev`          | test and lint tools, all algorithms |

## Quick start

```python
import os

# Configure before the first import of securitykit.api (see "Configuration").
os.environ.setdefault("HASH_VARIANT", "argon2")
os.environ.setdefault("PEPPER_MODE", "hmac")
os.environ.setdefault("PEPPER_HMAC_KEY", "replace-with-a-long-random-secret")

from securitykit.api import hash_password, verify_password

stored = hash_password("Correct-Horse-9-Battery")   # validates, then hashes
assert verify_password("Correct-Horse-9-Battery", stored)
```

`hash_password` checks the password against the password policy first
and raises `PasswordValidationError` if it is too weak.
`verify_password` does not apply the policy (so users with older, weaker
passwords can still log in) unless `PASSWORD_GATE_ON_VERIFY=true`.

## Upgrading hashes at login

When you raise the cost or change algorithm, old hashes keep working.
Upgrade them the next time the user logs in:

```python
from securitykit.api import authenticate_and_upgrade

ok, new_hash = authenticate_and_upgrade(password, user.password_hash)
if not ok:
    raise InvalidCredentials()
if new_hash is not None:
    user.password_hash = new_hash
    user.save()
```

The algorithm is detected from the stored hash (`$argon2…`, `$2b$…`,
`$scrypt$…`, `pbkdf2:…`). If it matches the current `HASH_VARIANT` the
hash is only replaced when the parameters changed; if it differs, the
password is migrated to the current algorithm. Pass `config=` to use a
mapping instead of `os.environ`.

## Using a specific configuration

The functions in `securitykit.api` read `os.environ` once, at import.
To work with an explicit mapping, build an algorithm directly:

```python
from securitykit.hashing.factory import HashingFactory

algo = HashingFactory({"HASH_VARIANT": "scrypt"}).get_algorithm()
stored = algo.hash("pw")
assert algo.verify(stored, "pw")        # note: (stored_hash, password)
assert not algo.needs_rehash(stored)
```

`Algorithm("argon2", config={...})` works the same way. To reload the
module-level API after changing the environment, call
`securitykit.api.password_security.reload_configuration()`.

## Configuration

All keys are strings in the environment or the mapping you pass.

**Algorithm**

| Key | Default | Notes |
|-----|---------|-------|
| `HASH_VARIANT` | `scrypt` | `argon2`, `bcrypt`, `scrypt`, `werkzeug_pbkdf2` |
| `ARGON2_TIME_COST` / `_MEMORY_COST` / `_PARALLELISM` | `2` / `65536` (KiB) / `1` | also `_HASH_LENGTH` 32, `_SALT_LENGTH` 16 |
| `BCRYPT_ROUNDS` | `12` | |
| `SCRYPT_N` / `_R` / `_P` | `131072` / `8` / `1` | N must be a power of two |
| `SCRYPT_MAXMEM` | 512 MiB | read from the environment only |
| `WERKZEUG_PBKDF2_ITERATIONS` | `600000` | method `pbkdf2:sha256` |

**Pepper**

| Key | Default | Notes |
|-----|---------|-------|
| `PEPPER_MODE` | `noop` | `hmac` (recommended), `prefix`, `suffix`, `prefix_suffix`, `interleave` |
| `PEPPER_HMAC_KEY` | – | required for `hmac` |
| `PEPPER_HMAC_ALGO` | `sha256` | any `hashlib` name |
| `PEPPER_SECRET` | – | value for the decoration modes, unless `PEPPER_PREFIX`/`_SUFFIX`/`_INTERLEAVE_TOKEN` is set |
| `PEPPER_INTERLEAVE_FREQ` | `0` | must be > 0 in `interleave` mode |
| `PEPPER_ENABLED` | `true` | set `false` to turn the pepper off |

**Password policy** (`PASSWORD_` + field name)

| Key | Default |
|-----|---------|
| `PASSWORD_MIN_LENGTH` | `8` |
| `PASSWORD_REQUIRE_UPPER` / `_LOWER` / `_DIGIT` / `_SPECIAL` | `true` |
| `PASSWORD_GATE_ON_VERIFY` | `false` |

## Pepper

With `PEPPER_MODE=hmac` the password is replaced by
`hex(HMAC(PEPPER_HMAC_KEY, password))` before it reaches the hashing
algorithm. A database leak alone is then not enough to crack the hashes;
the attacker also needs the key, which should live outside the database.

- **The key cannot be rotated.** Changing `PEPPER_HMAC_KEY` makes every
  existing hash fail to verify. There is no key ID in the stored hash.
- **bcrypt and long digests:** bcrypt only uses the first 72 bytes. The
  default `sha256` gives 64 hex characters and is fine; `sha512` gives 128
  and does not work with bcrypt.
- The decoration modes only add characters to the password. They are
  kept for compatibility with existing hashes, are not cryptographic, and
  log a warning.

## Benchmark

Find parameters that take about 250 ms on this machine (needs `[bench]`):

```bash
python -m securitykit.bench.bench --variant argon2 --target-ms 250 --export-file bench.env
```

It prints the best combination and nearby candidates, and optionally
writes them as `ARGON2_…=` lines. The pepper is turned off while
benchmarking so the timings reflect the algorithm alone.

`securitykit.bootstrap.ensure_env_config()` does the same at startup: if
the parameters for `HASH_VARIANT` are missing and `AUTO_BENCHMARK=1`, it
benchmarks and writes them to `.env.local`, with a SHA-256 checksum that
detects accidental edits. The checksum is not keyed, so it does not
protect against tampering. `PEPPER_*` keys are never written.

## Password policy

```python
from securitykit.password.factory import PasswordFactory
from securitykit.password.gate import PasswordGate

validator = PasswordFactory({"PASSWORD_MIN_LENGTH": "12"}).get_validator()
validator.validate("Correct-Horse-9-Battery")    # raises PasswordValidationError if weak

gate = PasswordGate(validator.policy)
gate.allow("short")                              # False: cheap check before hashing
```

## Project layout

```
src/securitykit/
  api/            public functions and login-time migration
  hashing/        Algorithm façade, factory, registries
    algorithms/   argon2, bcrypt, scrypt, wz_pbkdf2
    policies/     parameter dataclasses with bounds and warnings
  transform/pepper/  pepper strategies and the factory that applies them
  password/       policy, validator, strength evaluator, gate
  bench/          benchmark engine and CLI
  utils/config_loader/  env/mapping → typed dataclasses
  bootstrap.py    auto-benchmark at startup
tests_new/        pytest suite
```

## Development

```bash
make install   # venv with dev and bench extras
make test      # pytest with coverage
make lint      # ruff
```

## Limitations

- Not audited, and not used in production.
- `securitykit.api` reads its configuration once, at import.
- No pepper key rotation (see above).
- The pepper factory can pass the key as a native `secret` to algorithms
  that support one, but none of the bundled ones do: argon2-cffi's
  `PasswordHasher` has no `secret` parameter, so every algorithm uses the
  HMAC prehash.

## License

MIT, see [LICENSE](LICENSE).
