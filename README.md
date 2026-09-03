# Hoolicy

[![CI](https://github.com/openhoo/hoolicy/actions/workflows/ci.yml/badge.svg)](https://github.com/openhoo/hoolicy/actions/workflows/ci.yml)
[![Release](https://github.com/openhoo/hoolicy/actions/workflows/release.yml/badge.svg)](https://github.com/openhoo/hoolicy/actions/workflows/release.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

Understandable policy as code for repositories.

Hoolicy turns repeated repository, compliance, supply-chain, and product-quality checks into strict YAML policies. Simple rules stay simple. Complex structured rules use bounded CEL or a compile-time Go extension. `hoolicy check` never downloads policy code and never executes scripts from a policy pack.

## Quick start

Install a release binary, use the container, or build with Go 1.26+:

```sh
go install github.com/openhoo/hoolicy/cmd/hoolicy@v0.3.1
# or: docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/work:ro" -w /work ghcr.io/openhoo/hoolicy:v0.3.1 check
```

For rootless Podman, add `--userns=keep-id`. Mapping the caller UID lets the non-root image read private repository files without weakening their host permissions.

Create a useful starter policy:

```sh
hoolicy init --project my-service
hoolicy check
```

Default `standard` profile checks repository documentation, licensing, vulnerability reporting, Git naming, and artifact sources. `--profile strict` also requires literal container images to use `sha256` digests. `--profile empty` creates only the strict configuration skeleton.

## Small rules look small

```yaml
version: 1
project: payments-api
failOn: error
rules:
  - id: repository.security-policy
    title: Repository documents vulnerability reporting
    description: Requires SECURITY.md at repository root.
    rationale: A private reporting path reduces unsafe public disclosure.
    remediation: Add reviewed reporting and supported-version instructions.
    severity: error
    kind: files
    files: [SECURITY.md]
    spec:
      mode: require
      message: SECURITY.md is required
```

Every rule must explain what it checks, why it matters, and how to remediate it. Hoolicy rejects unknown fields, duplicate YAML keys, invalid rule specs, duplicate rule IDs, and unsafe paths.

## Commands

```text
hoolicy init       Create standard, strict, or empty starter policy
hoolicy validate   Compile configuration, packs, regexes, and CEL
hoolicy check      Evaluate policies offline
hoolicy fix        Preview safe fixes; --apply writes reviewed changes
hoolicy list       List active rules and their source
hoolicy explain    Show rationale, remediation, and control mappings
hoolicy test       Run pass and fail fixtures for policy packs
hoolicy baseline   Preview or apply reviewed finding baselines
hoolicy doctor     Diagnose policy, Git, lock, and CI inputs
hoolicy report     Compare JSON policy reports by fingerprints and digests
hoolicy evidence   Create or verify decision evidence and attestations
hoolicy waiver     Preview or apply an exact finding-bound waiver
hoolicy inventory  Emit workspace policy and ownership inventory
hoolicy serve      Run the optional loopback, GET-only reuse service
hoolicy migrate    Preview or apply supported format migrations
hoolicy pack       Add, update, or verify vendored packs
```

Reports: human text, JSON, SARIF 2.1.0, JUnit XML, GitHub step summaries, and GitLab Code Quality. Exit codes: `0` passed, `1` a new policy finding met `failOn`, `2` configuration or execution error.

Existing repositories can adopt policy without hiding debt. `hoolicy baseline create` previews an exact, digest-bound baseline; `--apply` writes it. Full checks continue to report existing findings while blocking only new or materially changed findings. See [baseline adoption and CI](docs/adoption.md).

## Standard packs

- `packs/repository`: Git branch, commit, and merge-request naming.
- `packs/supply-chain`: approved npm, NuGet, and OCI sources plus expiring security exceptions.
- `packs/product-quality`: translation-key parity and semantic Gherkin coverage.
- `packs/ci-workflow-security`: structured GitHub Actions and GitLab CI trust boundaries.
- `packs/artifact-evidence`: pinned SARIF, SBOM, test, and provenance evidence.
- `packs/dependency-governance`: lock, source, local-reference, and license governance.
- `packs/deployment-invariants`: parameterized Kubernetes, Compose, and Terraform plan invariants.
- `packs/api-contract-hygiene`: experimental OpenAPI consumption-evidence comparison.

Use this repository as a versioned remote pack source:

```yaml
packs:
  - name: repository
    git: https://github.com/openhoo/hoolicy.git
    ref: v0.3.1
    subdir: packs/repository
    with:
      branch_pattern: '^(feat|fix|chore)/[a-z0-9]+(?:-[a-z0-9]+)*$'
      commit_pattern: '^(feat|fix|chore)(\([a-z0-9-]+\))?!?: .+$'
      merge_request_title_pattern: '^(Draft: )?(feat|fix|chore)(\([a-z0-9-]+\))?!?: .+$'
      allowed_branches: [main]
      merge_request_title_maximum: 100
```

Run `hoolicy pack update repository` once. It resolves the Git ref, vendors the exact pack, and writes `hoolicy.lock` with commit and content digest. Later `validate` and `check` operate offline and fail on tampering.

## Guardrails for guardrails

- No runtime plugins, shell commands, network calls, or foreign code from YAML.
- Checks retain Git-aware file discovery and metadata through a read-only built-in fallback when the `git` executable is unavailable.
- CEL has static checking and a configurable cost cap, hard-limited to 1,000,000.
- Waivers require owner, HTTPS ticket, meaningful reason, narrow scope, creation date, and expiry within 90 days.
- Safe fixes are hash-bound, refuse dirty targets and symlinks, show a diff first, and require `--apply`.
- Pack tests require at least one passing and one failing fixture for every published rule.

Start with [rule authoring](docs/authoring-rules.md), [policy packs](docs/policy-packs.md), [decision evidence](docs/evidence.md), [monorepo workspaces](docs/workspaces.md), [architecture and threat model](docs/architecture.md), [compatibility](docs/compatibility.md), or [recovery](docs/recovery.md). Product intent and non-goals live in the [roadmap](ROADMAP.md); repository implementation and remaining external gates are tracked separately in [roadmap status](docs/roadmap-status.md). A generic repository-policy example lives in [examples/repository-policy](examples/repository-policy).

## Project status

Latest published release remains the version in `VERSION`. Current development source contains the roadmap implementation through the proposed v1 contracts, but it is not a v1 release until independent security review, remote CI, tagged publication, and artifact verification complete. Configuration version `1` is strict; the compile-time Go SDK may still evolve before `v1.0.0`.

Commits use Conventional Commits and are checked by Hooversion. After successful CI on protected `main`, Hooversion prepares the next release on a release branch and reports a protected release PR; review and merge that PR rather than recreating the release commit manually. The merge's successful CI finalizes the release commit and immutable tag, then the release workflow attaches signed binaries, an SPDX SBOM, provenance, and a signed multi-platform GHCR image. `feat` commits publish a minor release, `fix` and `perf` commits publish a patch release, and breaking changes publish a major release; non-release commits do not publish a version.

Apache-2.0. See [CONTRIBUTING.md](CONTRIBUTING.md) and [SECURITY.md](SECURITY.md).
