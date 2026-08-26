# Changelog

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
