# Compile-time Go SDK

Runtime plugins are intentionally unsupported. Build a custom binary when a rule needs organization-specific parsing or external Go libraries.

```go
package main

import (
    "context"
    "os"

    "github.com/openhoo/hoolicy"
    "github.com/openhoo/hoolicy/sdk"
)

func main() {
    code := hoolicy.Run(context.Background(), os.Args[1:], hoolicy.BuildInfo{
        Version: "company",
    }, func(registry *sdk.Registry) error {
        return registry.Register("company.custom", companyRule{})
    })
    os.Exit(code)
}
```

Implement `sdk.RuleKind`:

```go
type RuleKind interface {
    Validate(rule Rule) error
    Evaluate(ctx context.Context, input EvalContext, rule Rule) ([]Finding, error)
}
```

`Validate` must reject incomplete or ambiguous specs. `Evaluate` must be deterministic for the supplied repository snapshot and context. Do not perform network calls or mutate the repository. Populate a stable semantic `Key`; Hoolicy derives the fingerprint after evaluation.

The SDK is source-compatible only on a best-effort basis during `v0.x`. Pin the Hoolicy module version for custom builds.
