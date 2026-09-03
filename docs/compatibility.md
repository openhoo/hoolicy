# Compatibility and support

Hoolicy uses semantic versioning for the CLI and Go module. Stable on-disk contracts carry their own integer version: project config `1`, pack `1`, lock `1`, baseline `1`, waiver `1`, evidence policy `1`, evidence bundle `1`, and JSON report `2`.

Before `v1.0.0`, the latest published `v0` minor line receives support. The compatibility suite retains unchanged `v0.1` project and pack fixtures because the current on-disk version `1` originated there; the report migration suite upgrades JSON report v1 to v2. A future on-disk contract version must add immutable compatibility fixtures before release.

After `v1.0.0`, a documented stable field is not removed or reinterpreted in a minor release. New optional fields may appear. Consumers must ignore unknown report fields but configuration remains strict and rejects unknown policy input. Go SDK symbols follow normal Go module compatibility rules within major version `v1`.

The current and immediately previous on-disk version receive migration support for at least 12 months after replacement. `hoolicy migrate` is preview-first and never rewrites a file without `--apply`. JSON report v1 is migrated with the matching historical project configuration, lock, and vendored pack state:

```sh
hoolicy migrate report --config historical/hoolicy.yaml old-report.json
hoolicy migrate report --config historical/hoolicy.yaml --apply --output report-v2.json old-report.json
```

CLI flags and SDK APIs receive a warning for at least two minor releases before removal, except when continued support creates a confirmed critical security vulnerability. Security removals are documented in release notes with a safe replacement.

Exit codes are stable: `0` completed without blocking findings, `1` completed with findings at or above `failOn`, `2` invalid input, unsafe state, acquisition/verification failure, parser failure, resource-budget breach, or execution failure. `validate`, `check`, `test`, `fix`, report generation, inventory, migration preview, and evidence verification never use network acquisition implicitly.

Published schemas in `schemas/v1/` are immutable, versioned editor and integration contracts. Schemas in `schemas/` track the latest supported versions. Use the versioned URL in editor configuration so a future schema release cannot silently change validation. Runtime validation remains authoritative for cross-field rules, path safety, signature policy, compatibility ranges, and repository-state checks that JSON Schema cannot express.

YAML Language Server example:

```yaml
# yaml-language-server: $schema=https://raw.githubusercontent.com/openhoo/hoolicy/main/schemas/v1/hoolicy.schema.json
version: 1
project: example
```

`hoolicy pack init` emits equivalent directives for `pack.yaml` and `tests/cases.yaml`.
