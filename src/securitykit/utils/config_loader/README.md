# Config Loader

High-level, deterministic configuration → object construction pipeline used by SecurityKit
(for hashing policies, password policies, benchmarking parameters, etc.).

This module converts flat key/value mappings (e.g. `os.environ` or a dict) into *policy-like*
Python objects (dataclasses or plain classes) by introspecting `__init__` parameters.

---

## Table of Contents

1. Core Concepts
2. Design Goals
3. Quick Start
4. Parsing & Conversion Rules
5. Builder Resolution Logic
6. Error Handling & Logging
7. Schema Export (Documentation / Tooling)
8. Custom Converters
9. Value Sources (Extensibility)
10. Type Utilities
11. Testing Patterns
12. Best Practices
13. Troubleshooting
14. Roadmap / Future Extensions

---

## 1. Core Concepts

| Component            | Responsibility                                                |
|----------------------|---------------------------------------------------------------|
| `ConfigLoader`       | Public facade (`from_env()`, `build()`)                       |
| `PolicyBuilder`      | Introspects constructor, resolves & converts parameters       |
| `ValueSource`        | Abstract read-only key/value provider                        |
| `ConverterRegistry`  | Ordered chain of conversion functions                         |
| `default_parse`      | Heuristic parser for booleans, sizes, ints, floats, lists     |
| `export_schema`      | Introspects a class to produce a structured schema description|
| `normalize_type`     | Minimal helper for simplifying generic typing info           |

---

## 2. Design Goals

| Goal                     | Explanation                                                                 |
|--------------------------|-----------------------------------------------------------------------------|
| Predictable              | Single pass, explicit order, no silent fallbacks beyond defaults            |
| Transparent              | Logs every missing optional parameter (with its default)                   |
| Extensible               | Pluggable converters, future multi-layer sources                           |
| Minimal API Surface      | One primary entry point (`ConfigLoader.build`)                             |
| Fail Fast                | Aggregates all missing/invalid issues before raising                       |
| Side-Effect Free         | Pure mapping in → object out (no global state mutation)                     |

---

## 3. Quick Start

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader, export_schema

# Your policy / settings object
@dataclass
class Argon2Policy:
    time_cost: int = 2
    memory_cost: int = 65536
    parallelism: int = 1
    hash_length: int = 32
    salt_length: int = 16

config = {
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "64k",     # size unit → 65536
    "ARGON2_PARALLELISM": "2",
    # HASH_LENGTH & SALT_LENGTH omitted → defaults + warnings
}

loader = ConfigLoader(config)
policy = loader.build(Argon2Policy, prefix="ARGON2_", name="argon2 policy")

assert policy.time_cost == 3
assert policy.memory_cost == 65536
assert policy.hash_length == 32
```

Export a machine‑readable schema (can feed docs generation):

```python
rows = export_schema(Argon2Policy, prefix="ARGON2_")
# [
#   {'param': 'time_cost', 'config_key': 'ARGON2_TIME_COST', 'required': False, 'default': 2, 'type': 'int'},
#   ...
# ]
```

---

## 4. Parsing & Conversion Rules (`default_parse`)

Order (first matching wins):

1. Non-strings → returned unchanged
2. Boolean tokens:
   - True: `true`, `on`, `yes`
   - False: `false`, `off`, `no`
   - (Note: `"1"` / `"0"` intentionally NOT treated as booleans to avoid ambiguity)
3. Size strings: `64k`, `32M`, `1G`, `8kb`, `1024`, etc.
4. Integer pattern: `^-?[0-9]+$`
5. Float pattern: `^-?[0-9]+\.[0-9]+$`
6. Lists: contains `,` or `;` → split on both separators, trimmed
7. Fallback: original string

Examples:

| Raw         | Parsed          |
|-------------|-----------------|
| `"true"`    | `True`          |
| `"64k"`     | `65536`         |
| `"5M"`      | `5242880`       |
| `"42"`      | `42`            |
| `"-7.5"`    | `-7.5`          |
| `"a,b;c"`   | `["a", "b", "c"]` |
| `" 10 "`    | `10`            |
| `"value"`   | `"value"`       |

---

## 5. Builder Resolution Logic (`PolicyBuilder._collect`)

For each parameter in the target class signature:

1. Construct key: `PREFIX + PARAM_NAME_UPPER`
2. If key present:
   - Convert via `ConverterRegistry.convert`
   - On converter exception → accumulate error
3. Else if parameter has no default → accumulate “Missing required …”
4. Else (optional):
   - Use default
   - Log warning: optional config missing (prefix + default value)
5. After loop:
   - If any errors accumulated → raise `ConfigValidationError` with all messages
6. Instantiate target class with resolved mapping
   - If constructor throws → wrap in `ConfigValidationError`

This *batch reporting* means user sees all problems at once.

---

## 6. Error Handling & Logging

| Scenario                            | Behavior |
|------------------------------------|----------|
| Missing required key               | Collected → raised in final `ConfigValidationError` |
| Invalid converter transformation   | Collected with detail message                      |
| Constructor raises (`__init__`)    | Wrapped in `ConfigValidationError`                 |
| Optional key missing               | Warning logged (not an exception)                  |
| No parameters at all / empty class | Succeeds with no warnings                          |

Example error message:
```
Errors building argon2 policy: Missing required 'ARGON2_MEMORY_COST'; Invalid value for 'ARGON2_TIME_COST': invalid literal ...
```

---

## 7. Schema Export

`export_schema(policy_cls, prefix)` introspects:

| Field      | Meaning                                 |
|------------|------------------------------------------|
| `param`    | Original constructor parameter name      |
| `config_key` | Derived env/config key (`PREFIX + UPPERCASE`) |
| `required` | `True` if no default                     |
| `default`  | Default value or `None`                  |
| `type`     | From annotation (falls back to `str(type)`) |

Usage ideas:
- Generate README tables
- Validate config coverage in CI (e.g. ensure all required keys are present)
- Feed a web UI for editing configuration

---

## 8. Custom Converters

You can inject domain-specific parsing **before** or **after** the default chain:

```python
from securitykit.utils.config_loader import ConverterRegistry, ConfigLoader

def parse_percent(value):
    if isinstance(value, str) and value.endswith("%"):
        return float(value[:-1]) / 100.0
    return value

registry = ConverterRegistry()
registry.register_front(parse_percent)  # runs before default_parse

cfg = {"APP_SUCCESS_RATE": "75%"}
@dataclass
class AppPolicy:
    success_rate: float = 0.95

loader = ConfigLoader(cfg, converters=registry)
policy = loader.build(AppPolicy, prefix="APP_", name="app")
assert policy.success_rate == 0.75
```

Chain semantics:
- Each converter receives the output of the previous.
- Must be pure (no side-effects) for predictability.

---

## 9. Value Sources

Current implementation: `ValueSource(mapping)` wraps any `Mapping[str, Any]`.

Future extension ideas:
- Composed / layered sources (precedence: explicit overrides → env → file → defaults)
- Remote secret manager integration (lazy fetch)
- Snapshotting / diff reporting for dynamic reconfiguration

---

## 10. Type Utilities (`normalize_type`)

Currently:
- Returns original type if no generic origin
- Converts `list[int]` → `list`
- Converts `Optional[T]` / `Union[T, None]` → `Union` origin
- Placeholder for future advanced normalization (e.g. nested generics flattening)

Use case: Provide simplified type names in exported schema.

---

## 11. Testing Patterns

Common patterns already in the test suite:

| Pattern                                | Intent |
|----------------------------------------|--------|
| Patch mapping to simulate env presence | Deterministic resolution |
| Test all converters via parametrization | Confidence in parsing invariants |
| Negative tests raising `ConfigValidationError` | Validation of aggregated error reporting |
| Schema export assertions                | Guard against breaking doc generation |
| Custom converter injection test         | Ensure chain order preserved |

Fixture examples (suggested):
```python
@pytest.fixture
def loader_factory():
    def _make(mapping, registry=None):
        return ConfigLoader(mapping, converters=registry)
    return _make
```

---

## 12. Best Practices

| Practice | Reason |
|----------|--------|
| Keep constructors “dumb” | Validation logic should throw early and clearly |
| Provide sensible defaults | Enables soft adoption – warnings surface omissions |
| Avoid booleans encoded as 1/0 | Ambiguous with numeric parameters |
| Keep prefixes consistent (e.g. `PASSWORD_`) | Discoverability + tooling simplicity |
| Centralize variant keys in a constants module | Single source of truth (e.g. `ENV_VARS`) |
| Fail fast in CI when required keys absent | Prevent runtime surprises |
| Avoid hidden mutation in converters | Idempotence & easier debugging |

---

## 13. Troubleshooting

| Symptom | Cause | Fix |
|---------|-------|-----|
| Value logged as string instead of int | Did not match int/float pattern | Trim whitespace; ensure numeric regex |
| A boolean stayed as string `"True"` | Capitalization + not stripped | Use lowercase tokens (`true`, `false`) |
| List parsing didn’t happen | No `,` or `;` in raw string | Provide correct delimiters |
| Missing required key not caught | Constructor supplies its own default | Make param default-less if truly required |
| Unexpected huge number (e.g. memory) | `64m` vs `64M` – both valid → multiplication | Confirm intent; sizes are binary (×1024) |
| Multiple errors but only one shown | Older code path or early raise | Confirm using current aggregated version |

---

## 14. Roadmap / Future Extensions

| Idea | Benefit |
|------|---------|
| Layered `ValueSource` chain | Environment overrides + .env.local + remote defaults |
| Strict typing enforcement pass | Catch mismatched types post-conversion |
| Pluggable validation hooks | Domain-specific constraints (ranges, enums) |
| Schema → JSON Schema export | IDE autocomplete / external tooling |
| Live reload support | Dynamic config changes without restart |
| Metrics integration (conversion stats) | Operational observability |

---

## Appendix: Minimal Integration Example

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader, ConverterRegistry

@dataclass
class PasswordPolicy:
    min_length: int = 12
    require_upper: bool = True
    require_lower: bool = True
    require_digit: bool = True
    require_special: bool = True

cfg = {
    "PASSWORD_MIN_LENGTH": "16",
    "PASSWORD_REQUIRE_UPPER": "false",
}

loader = ConfigLoader(cfg)
policy = loader.build(PasswordPolicy, prefix="PASSWORD_", name="PasswordPolicy")

assert policy.min_length == 16
assert policy.require_upper is False
assert policy.require_digit is True
```

---

## License / Usage

This module is part of the **SecurityKit** internal utility stack. Use as a stable internal API; external consumers should prefer higher-level interfaces where available unless extending policy creation.

---

**Questions or ideas?** Extend with a custom converter or open an internal issue referencing this module.
