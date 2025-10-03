# Config Loader

Deterministic, test‑friendly configuration → object construction used across SecurityKit
(hash policies, password policies, benchmark parameters, pepper configs, etc.).

It converts a flat key/value mapping (e.g. `os.environ` or any `Mapping[str, Any]`)
into strongly‑typed Python objects (dataclasses or plain classes) by introspecting
the target class constructor.

---

## Table of Contents

1. Core Concepts  
2. Design Goals  
3. Quick Start  
4. Parsing & Conversion Rules  
5. Resolution & Type Enforcement Pipeline  
6. Error Handling & Logging  
7. Schema Export (Documentation / Tooling)  
8. Custom Converters  
9. Value Sources & (Future) Layering  
10. Type Utilities  
11. Refactored Builder (Decomposition)  
12. Testing Patterns  
13. Best Practices  
14. Troubleshooting  
15. Roadmap / Future Extensions  
16. Appendix: Minimal Integration Example  

---

## 1. Core Concepts

| Component              | Responsibility                                                        |
|------------------------|------------------------------------------------------------------------|
| `ConfigLoader`         | Public façade (`build()`) orchestrating value resolution               |
| `PolicyBuilder`        | Introspection + collection + primitive type enforcement                |
| `ValueSource`          | Read‑only provider over a mapping                                       |
| `ConverterRegistry`    | Ordered chain of stateless conversion functions                        |
| `default_parse`        | Heuristic parser (bool, size units, ints, floats, list, passthrough)   |
| `export_schema`        | Introspect class → structured rows (param metadata)                    |
| `normalize_type`       | Simplify generic / annotated types for schema output                   |

---

## 2. Design Goals

| Goal          | Explanation                                                                 |
|---------------|-----------------------------------------------------------------------------|
| Predictable   | Single linear pass over constructor params                                  |
| Transparent   | Logs every missing optional with the chosen default                         |
| Extensible    | Pluggable converters (front/back insertion)                                   |
| Fail Fast     | Aggregates *all* missing/invalid errors (batch report)                      |
| Pure          | Mapping in → object out (no hidden global mutation)                        |
| Auditable     | Schema export enables docs / diff tooling                                   |
| Testable      | Small, orthogonal layers; easy monkeypatch / fixture injection              |

---

## 3. Quick Start

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader, export_schema

@dataclass
class Argon2Policy:
    time_cost: int = 2
    memory_cost: int = 65536
    parallelism: int = 1
    hash_length: int = 32
    salt_length: int = 16

cfg = {
    "ARGON2_TIME_COST": "3",
    "ARGON2_MEMORY_COST": "64k",    # size unit → 65536
    "ARGON2_PARALLELISM": "2",
    # HASH_LENGTH & SALT_LENGTH omitted → defaults + warnings
}

loader = ConfigLoader(cfg)
policy = loader.build(Argon2Policy, prefix="ARGON2_", name="Argon2Policy")

assert policy.time_cost == 3
assert policy.memory_cost == 65536
assert policy.hash_length == 32  # default applied
```

Schema export:

```python
rows = export_schema(Argon2Policy, prefix="ARGON2_")
# [
#   {'param': 'time_cost', 'config_key': 'ARGON2_TIME_COST', 'required': False,
#    'default': 2, 'type': 'int'},
#   ...
# ]
```

---

## 4. Parsing & Conversion Rules (`default_parse`)

Order (first match wins):

1. Non‑string → returned as‑is  
2. Boolean tokens (case‑insensitive):  
   - True: `true`, `yes`, `on`  
   - False: `false`, `no`, `off`  
   (Deliberately *not* interpreting `"1"` / `"0"` as booleans to avoid ambiguity)
3. Size strings: `64k`, `32M`, `1G`, `8kb`, raw numeric (`1024`)  
4. Int pattern: `^-?[0-9]+$`  
5. Float pattern: `^-?[0-9]+\.[0-9]+$`  
6. List (contains `,` or `;`) → split on both, trim, drop empties  
7. Fallback: original (stripped) string

| Raw        | Parsed               |
|------------|----------------------|
| `"true"`   | `True`               |
| `"64k"`    | `65536`              |
| `"5M"`     | `5242880`            |
| `"42"`     | `42`                 |
| `"-7.5"`   | `-7.5`               |
| `"a,b;c"`  | `["a", "b", "c"]`    |
| `" 10 "`   | `10`                 |
| `"value"`  | `"value"`            |

---

## 5. Resolution & Type Enforcement Pipeline

`PolicyBuilder._collect` has been refactored into smaller steps:

1. Introspect `__init__` signature (ordered parameters)
2. For each param:
   - Derive key: `PREFIX + UPPER(param)`
   - If present: convert via `ConverterRegistry.convert`
   - Else if no default: record “Missing required …”
   - Else: use default + log warning
3. If collection errors → raise aggregated `ConfigValidationError`
4. Primitive type enforcement pass:
   - Only `int`, `float`, `bool` (exact annotations)
   - If value already correct → accept
   - For `int` / `float`: attempt coercion (e.g. `"5"` → `5`); failure → type mismatch error
   - For `bool`: **no coercion** (must already be a bool after conversion phase)
5. If type errors → aggregated raise
6. Instantiate target class
7. Wrap constructor exceptions in `ConfigValidationError`

Why a second pass?  
Separation clarifies which failures are raw parsing vs. mismatched declared types (especially when a converter leaves a value as string).

---

## 6. Error Handling & Logging

| Scenario                          | Behavior                                                            |
|----------------------------------|---------------------------------------------------------------------|
| Missing required key             | Accumulated → batch raise                                           |
| Converter failure                | Accumulated with detailed message                                   |
| Primitive type mismatch          | Collected in enforcement pass                                       |
| Optional missing                 | Warning (includes default)                                          |
| Constructor raised               | Wrapped into `ConfigValidationError`                                |
| Multiple issues                  | Single aggregated message                                           |

Example aggregated message:

```
Errors building Argon2Policy: Missing required 'ARGON2_MEMORY_COST'; Type mismatch for 'ARGON2_TIME_COST': expected int, got str
```

---

## 7. Schema Export

`export_schema(cls, prefix)` yields metadata rows:

| Field        | Description                                  |
|--------------|----------------------------------------------|
| `param`      | Constructor parameter name                   |
| `config_key` | Derived key (`PREFIX + UPPER`)               |
| `required`   | True if no default                           |
| `default`    | Default value or `None`                      |
| `type`       | Simplified annotation (via `normalize_type`) |

Use Cases:
- Generate README tables
- CI coverage audits (ensuring required keys exist)
- Editor / UI forms
- Auto documentation snapshots

---

## 8. Custom Converters

Front vs. back registration:

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConverterRegistry, ConfigLoader

def parse_percent(v):
    if isinstance(v, str) and v.endswith("%"):
        return float(v[:-1]) / 100.0
    return v

registry = ConverterRegistry()
registry.register_front(parse_percent)  # runs before default_parse

cfg = {"RATE_SUCCESS": "75%"}
@dataclass
class RatePolicy:
    success: float = 0.9

policy = ConfigLoader(cfg, converters=registry).build(RatePolicy, prefix="RATE_", name="RatePolicy")
assert policy.success == 0.75
```

Guidelines:
- Converters must be pure / side‑effect free
- Order matters (front vs. back)
- Return original value if not applicable

---

## 9. Value Sources & Future Layering

Current: `ValueSource(mapping)`  
Planned extensions:
- Layer precedence chain (override → env → file → defaults)
- Dynamic remote secret resolution
- Diff snapshot API for hot‑reload diagnostics

---

## 10. Type Utilities (`normalize_type`)

Current behavior:
- Returns object if no generic origin
- Collapses `list[int]` → `list`
- Simplifies `Optional[T]` to its origin
- Leaves complex unions mostly untouched (subject to future enhancement)

Purpose: stable, human‑readable `type` column in exported schema.

---

## 11. Refactored Builder (Decomposition)

Internals (illustrative):

| Helper Method              | Responsibility                     |
|---------------------------|------------------------------------|
| `_iter_parameters`        | Signature iteration                |
| `_resolve_values`         | Raw value fetch + default logging  |
| `_enforce_primitive_types`| Post-collection type enforcement   |
| `_raise_if_errors`        | Aggregated raise helper            |
| `_collect`                | Orchestrates the above             |

Benefits: granularity for unit tests (e.g. simulate isolated type pass failures).

---

## 12. Testing Patterns

| Pattern                                 | Goal                                  |
|-----------------------------------------|---------------------------------------|
| Roundtrip build with mixed defaults     | Ensure warnings and defaults ok       |
| Invalid numeric → aggregated error      | Batch reporting works                 |
| Bool mismatch remains string            | Triggers type mismatch properly       |
| Custom converter front/back insertion   | Ordering guaranteed                   |
| Schema export snapshot                  | Breaking changes detection            |
| Large list parsing                      | Separator logic correct               |

Minimal negative test:

```python
@dataclass
class R:
    a: int
    b: int = 5

cfg = {"R_A": "not_int"}
with pytest.raises(ConfigValidationError):
    ConfigLoader(cfg).build(R, prefix="R_", name="RPolicy")
```

---

## 13. Best Practices

| Practice                                | Reason                                  |
|-----------------------------------------|-----------------------------------------|
| Keep constructors minimal               | Validation localized & explicit         |
| Use explicit defaults                   | Optional omissions visible via warnings |
| Avoid 1/0 booleans                      | Ambiguity with numeric types            |
| Standardize prefixes                    | Predictable mapping / tooling           |
| Centralize key constants                | Fewer drift points                      |
| Add new converters via registry         | Separation of concerns                  |
| Avoid implicit coercion for bool        | Prevent surprise booleanization         |

---

## 14. Troubleshooting

| Symptom                            | Cause                                    | Fix |
|-----------------------------------|------------------------------------------|-----|
| Value still string, expected int  | Pattern mismatch                         | Check numeric format / whitespace |
| Bool not parsed                   | Non‑boolean token                        | Use accepted strings (`true/false/...`) |
| Missing required not reported     | Parameter actually has a default         | Remove default if truly required |
| Type mismatch after conversion    | Converter left incompatible type         | Adjust converter or refine annotation |
| Only first error reported         | Older version / early raise path         | Upgrade to current aggregated logic |

---

## 15. Roadmap / Future Extensions

| Idea                          | Benefit                                 |
|------------------------------|-----------------------------------------|
| Layered sources              | Priority stacking (override semantics)  |
| Post-build validation hooks  | Range / enum constraints                |
| JSON Schema export           | External UI / IDE integration           |
| Live reload diff API         | Observability for dynamic configs       |
| Metrics instrumentation      | Operational telemetry                   |
| Declarative field metadata   | Inline docs / richer schema output      |

---

## 16. Appendix: Minimal Integration Example

```python
from dataclasses import dataclass
from securitykit.utils.config_loader import ConfigLoader

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

policy = ConfigLoader(cfg).build(PasswordPolicy, prefix="PASSWORD_", name="PasswordPolicy")

assert policy.min_length == 16
assert policy.require_upper is False
assert policy.require_digit is True
```

---

## License / Usage

Internal utility of **SecurityKit**. External consumers typically use higher layers (factory/API) unless implementing new policy types or advanced config workflows.

Questions or proposals? Open an issue referencing this module and include:
- Target class
- Example raw mapping
- Desired parsing behavior
- Any custom converter logic
