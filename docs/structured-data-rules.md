# Structured configuration field policies

`structured.fields` checks configuration fields without requiring a CEL
expression. Use JSON pointers to govern JSON, YAML, and TOML configuration.
Checks run offline against the repository inventory; policies cannot execute
commands or download configuration.

```yaml
- id: service.production-settings
  title: Production services use approved settings
  description: Validate service identity, TLS, ports, roles, and secret-free configuration.
  rationale: Production defaults must remain within the approved service contract.
  kind: structured.fields
  severity: error
  files: ["services/*/config.yaml"]
  remediation: Set service configuration to the approved production defaults.
  spec:
    format: yaml
    fields:
      - pointer: /service/name
        required: true
        type: string
        pattern: '^api-[a-z0-9-]+$'
      - pointer: /service/tls/enabled
        required: true
        allowedValues: [true]
      - pointer: /service/port
        required: true
        type: integer
        minimum: 1
        maximum: 65535
      - pointer: /service/roles
        required: true
        type: array
        minItems: 1
        maxItems: 8
        uniqueItems: true
        requiredItems: [reader]
      - pointer: /service/debugToken
        forbidden: true
```

## Specification

| Field | Behavior |
| --- | --- |
| `format` | Optional `auto`, `json`, `yaml`, `yml`, or `toml`. The default detects format from the filename using Hoolicy's document parser. |
| `fields` | Required list of 1–256 field constraints. Duplicate pointers are rejected. |
| `allowNoFiles` | Defaults to `false`; no matching files produces a finding. Set `true` for optional configuration. |
| `message` | Optional prefix applied to individual field findings. |

Every field constraint requires an explicit `pointer`. The empty string selects
the document root. `/service/name` selects an object key; `/roles/0` selects the
first array element. Escape `/` inside key names as `~1` and `~` as `~0`.
Array indices must be canonical nonnegative decimal integers: `0` is valid,
while `01`, `-1`, `+1`, and `-` do not select an element. Wildcards are not
supported; select files with `files` and `exclude` patterns.

| Constraint | Behavior |
| --- | --- |
| `required: true` | The pointer must exist. Explicit `null` counts as present. |
| `forbidden: true` | The pointer must be absent, including values set to `null`. Cannot be combined with other constraints. |
| `type` | One of `string`, `number`, `integer`, `boolean`, `array`, `object`, `null`. An integer is a numeric value with no fractional part. |
| `allowedValues` | A list of 1–256 accepted values. A singleton list expresses equality; `[null]` requires a present null value when combined with `required`. Comparison checks complete object and array contents; equivalent numeric representations such as `1`, `1.0`, and `1e0` compare equally. |
| `pattern` | Go regular expression matched against a string. Use `^` and `$` to require a whole-string match. Limited to 4096 bytes. |
| `minimum`, `maximum` | Inclusive finite numeric bounds. Numeric strings do not count as numbers. |
| `minItems`, `maxItems` | Inclusive nonnegative array length limits. |
| `uniqueItems: true` | Array elements must have distinct normalized values; objects with the same keys and values are duplicates regardless of key order. |
| `requiredItems` | A list of 1–256 values that must occur in an array. Complete objects can be required as well as scalars. |

A missing field is skipped unless `required: true` is present. Thus a type or
value constraint can validate an optional field. A path that traverses a scalar,
a missing parent, or an invalid array index is missing. Use `required` to reject
such a path and a separate parent constraint to describe the required container
shape. Numeric bounds require numbers and item constraints require arrays even
when `type` is omitted. Conflicting explicit types, reversed bounds, invalid
regular expressions, unknown fields, and empty value lists are configuration
errors.

Each document in a YAML stream is checked independently. An empty YAML file
produces a finding. Invalid syntax and duplicate object keys remain operational
errors rather than accepted policy violations. Findings identify the file,
document, pointer, and failed constraint. YAML locations identify the document
start; JSON and TOML locations are at the beginning of the file. Findings omit
actual and expected configuration values to keep sensitive values out of
reports. Parser errors can include invalid input tokens, so avoid using policy
reports as an unrestricted channel for confidential configuration.

JSON numbers retain their original decimal and exponent tokens before rational
comparison, within the documented comparison limits. For example,
`9007199254740993e0` does not equal `9007199254740992`, and
`1.0000000000000000001` is not an integer. YAML and TOML retain their existing
parser representations: floating values may already have been rounded to
`float64` before comparison. Policy constants follow policy YAML parsing;
`minimum` and `maximum` explicitly use `float64`. This does not guarantee
arbitrary decimal precision for numeric policy constants. Very large integer
constants are exact only when representable by the policy parser's integer
types. Other rule kinds retain the existing normalized document input.

Value comparisons allow at most 100000 items in every compared array (including nested arrays) and 128 nesting levels. Numeric type checks, bounds, and value comparisons allow numeric text up to 4096 bytes and exponent magnitude up to 4096; exceeding these limits is an operational error. Required-item membership uses a single indexed pass over the array.
The kind preserves cancellation between files, field constraints, and array comparisons and uses
the shared document parse cache. It does not offer automatic fixes.
