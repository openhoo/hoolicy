# Policy explanations example

This example deliberately returns exit **1**: `production.yaml` enables debug
mode, while the policy requires `false`. It exercises the explanation metadata
supported by the current source. Build a binary containing this feature first.

From the Hoolicy source root:

```sh
go run ./cmd/hoolicy check --config examples/policy-explanations/hoolicy.yaml
go run ./cmd/hoolicy explain --config examples/policy-explanations/hoolicy.yaml service.production-debug
go run ./cmd/hoolicy check --config examples/policy-explanations/hoolicy.yaml --format json
```

The report names `service.production-debug`, explains the expectation and risk,
lists concrete steps and a reference, and marks the occurrence as blocking.
Change `debug` to `false` in a copy of the example and rerun to obtain exit 0.
Malformed YAML produces an operational diagnostic and exit 2 instead.

See [the full authoring and report guide](../../docs/policy-explanations.md).
