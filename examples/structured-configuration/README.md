# Structured configuration example

With Hoolicy 0.5 or newer, run from this directory:

```sh
hoolicy validate
hoolicy check
```

The provided production.yaml passes. Change `debug` to `true`, `replicas` to
`1`, or repeat `health` in `capabilities` to see precise field findings and
exit 1. Add `credentials: {password: null}` to demonstrate that forbidden
fields remain forbidden even when their value is null. Malformed YAML returns
exit 2. No package manager, network acquisition, or external service is needed.

The same rule kind supports JSON and TOML. Adapt the file glob, field pointers,
and bounds to a real application's contract before adopting the policy.
