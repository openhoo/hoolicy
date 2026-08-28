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

`Validate` must reject incomplete or ambiguous specs. `Evaluate` must be deterministic for the supplied repository snapshot and context. Do not perform network calls or mutate the repository. Populate message, location, properties, optional fix, and a stable semantic `Key`. Hoolicy binds rule ID, title, severity, remediation, controls, pack, and fingerprint to the validated configured rule after evaluation.

The complete [custom-rule example](../examples/custom-rule/main.go) is compiled by `go test ./...` on every supported CI platform.

Before `v1.0.0`, pin the Hoolicy module version. From `v1`, SDK symbols follow the compatibility and deprecation policy in [compatibility.md](compatibility.md).
