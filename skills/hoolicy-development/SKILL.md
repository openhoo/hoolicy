---
name: hoolicy-development
description: Develop and verify Hoolicy's Go policy engine, strict schemas, built-in rules and packs, reports, safe fixes, baselines, waivers, and evidence contracts. Use in a Hoolicy source checkout.
---

# Hoolicy development

Read `CONTRIBUTING.md` and the relevant architecture/compatibility guide in
`docs/`. Use Go 1.26+ as pinned by `go.mod`/CI; Git metadata and Docker are needed
for their corresponding integration checks. Commands run at the source root.

## Find the implementation

| Surface | Source |
| --- | --- |
| Commands and exit behavior | `cmd/hoolicy/`, `internal/cli/` |
| Strict config/document parsing | `internal/config/`, `internal/document/`, `schemas/` |
| Evaluation and rule kinds | `internal/engine/`, `internal/rules/` |
| Git-aware inventory/path safety | `internal/repository/`, `internal/safepath/` |
| Pack resolution/archive safety | `internal/packs/`, `internal/packarchive/`, `internal/ocipack/` |
| Pack fixtures | `packs/<pack>/tests/cases.yaml`, `internal/policytest/` |
| Fixes and evidence | `internal/fix/`, `internal/evidence/` |
| Report formats | `internal/report/` |
| Public compile-time extensions | `sdk/`, `examples/custom-rule/` |

## Verify a change

```bash
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/hoolicy test packs/repository packs/supply-chain packs/product-quality
go run ./cmd/hoolicy check
```

Start with affected package tests; use `gofmt` on changed Go files. Run the
specific additional pack's tests when changing it. New published pack rules
need both pass and fail fixtures; verify the actual failure reason rather than
only an exit code. A sample expected to pass cannot be validated solely with
the real repository's possibly unrelated findings.

## Maintain public contracts

- Keep unknown-field/duplicate-key rejection, rule-ID uniqueness, schema/spec
  validation, and safe repository-relative paths. Never make YAML execute shell,
  runtime plugins, or foreign downloaded code.
- CEL is statically checked and cost-bounded; compile-time Go extensions use
  the SDK. Preserve cancellation/budgets and fail-closed operational errors.
- Checks use exact vendored packs and verify lock/digest integrity offline.
  Download/resolution belongs to explicit pack update, not ordinary check.
- Safe fixes preview first, are hash-bound, reject dirty targets and symlinks,
  and apply only with `--apply`. Add race/path regressions for boundary changes.
- Baselines match exact findings/policy digests; waivers remain narrow, owned,
  ticketed, and expiring. Do not turn operational errors into accepted debt.
- Reports preserve stable fingerprints, escaping, safe locations, and exit
  contracts: 0 pass, 1 blocking new finding, 2 operational/configuration failure.
- Evidence verification distinguishes complete decisions from artifacts that
  merely exist. Versioned schemas and compatibility fixtures are public contracts.

For a rule change update its implementation, schema, pack spec/fixtures, and
`docs/authoring-rules.md` or relevant pack guide together. For contract changes
inspect `docs/compatibility.md`, `schemas/v1/`, and `compatibility_test.go`.
Release files/actions use `VERSION` and synchronization scripts; skill edits
do not require a release bump. Report actual checks and bounded reproduction.
