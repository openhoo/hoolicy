# Contributing

Issues and focused pull requests welcome.

Requirements: Go 1.26+, Git, and Docker for container verification.

```sh
go test ./...
go test -race ./...
go vet ./...
go run ./cmd/hoolicy test packs/repository packs/supply-chain packs/product-quality
go run ./cmd/hoolicy check
```

Run `gofmt` on Go changes. Add positive and negative tests for new behavior. A new built-in pack rule requires both pass and fail fixtures. Security-sensitive path, pack, waiver, or fix changes need regression tests.

Use Conventional Commits. Keep pull requests small enough to review. Explain user-visible behavior, threat-model changes, and compatibility impact.

By contributing, you agree that your contribution is licensed under Apache-2.0.
