# Changelog

## 0.2.3 (2026-08-30)

### Bug Fixes

- **packs:** make Hoostack dogfood reliable (d30dbe7)
- **ci:** isolate dogfood comparison inputs (7db27da)

## 0.2.2 (2026-08-29)

### Bug Fixes

- **hoolicy:** harden policy execution boundaries (5838482)

## 0.2.1 (2026-08-28)

### Bug Fixes

- **hoolicy:** harden archive extraction boundary (9b35d63)

## 0.2.0 (2026-08-28)

### Features

- **hoolicy:** implement roadmap policy capabilities (1bde0c9)

### Bug Fixes

- harden policy evaluation and release paths (6eae209)
- harden policy validation (f22fcae)
- close linked-worktree metadata handles [skip ci] (ceef9db)
- rebuild releases created before version manifest [skip ci] (d56395e)
- bound release asset replacement [skip ci] (933fb9e)
- anchor release version markers (081c2b0)
- **hoolicy:** enforce portable repository paths (7c80946)

### Other Changes

- record published footprint measurements (a1e1eb0)
- remove legacy references and add release recovery [skip ci] (8fc0327)

## 0.1.2 (2026-08-27)

### Performance

- accelerate policy checks and shrink runtime image

### Other Changes

- use node 24 docker actions
- add product roadmap
- add hooversion release automation
- invoke hooversion CLI directly

All notable changes follow Keep a Changelog conventions. Releases use semantic versioning.

## [0.1.1] - 2026-08-26

### Fixed

- Resolve version and available VCS metadata from Go build information when installed with `go install`.

## [0.1.0] - 2026-08-26

### Added

- Strict one-file YAML configuration with nine built-in rule kinds.
- Bounded CEL for structured JSON, YAML, TOML, XML, dotenv, and INI policy.
- Local and digest-locked Git-vendored policy packs with mandatory pass/fail fixtures.
- Expiring, owned, ticketed waivers and stale-waiver detection.
- Hash-bound safe fix preview and atomic apply workflow.
- Text, JSON, SARIF, and JUnit reports.
- Repository, supply-chain, and product-quality standard packs.
- Compile-time Go extension API.
- Multi-platform release, SBOM, provenance, Sigstore signing, and GHCR automation.

[0.1.0]: https://github.com/openhoo/hoolicy/releases/tag/v0.1.0
[0.1.1]: https://github.com/openhoo/hoolicy/releases/tag/v0.1.1
