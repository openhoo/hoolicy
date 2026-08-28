# Curated pack measurements

Measurement date: 2026-08-28. Every source is pinned below. Tests used a `-trimpath` build from this working tree, copied the exact local pack into an untracked `.hoolicy-measure/packs` directory, and ran `hoolicy check --format json`. Evaluation stayed offline after source or release-asset acquisition. Measurement overlays and report files were not part of the source snapshots.

## Pack identities

| Pack | Release | Tree digest | Fixture result |
| --- | --- | --- | --- |
| `ci-workflow-security` | 0.1.0 | `sha256:0b8420d1cf94744e4e99a537e93246fc19bb01f7590ac9c7d889b8361d2f4aad` | 12/12 |
| `dependency-governance` | 0.1.0 | `sha256:661ae7f32c71bf81f31d3019760f3fb47ea46dd52271b2a4846f37e9ce2edc88` | 11/11 |
| `deployment-invariants` | 0.1.0 | `sha256:e5d6d4ac8919b8c8160e574eadcbbb730a531065797c4e92b8c777cd9491793b` | 16/16 |
| `api-contract-hygiene` | 0.1.0 | `sha256:c2e5e5e1d16bee5df6e3e4a32e5f8a29c0ce264e41df1da3a6544a95ab98c40a` | 4/4 |
| `artifact-evidence` | 0.1.0 | `sha256:ec3b5a656bf95b044b6e2818115296f95136e934b10783c339e9825c50e0582e` | 4/4 |

`hoolicy pack verify packs/<name>` reproduces fixture counts and tree digests.

## Repository snapshots

| Source | Exact revision | Packs exercised |
| --- | --- | --- |
| [GitHub CLI](https://github.com/cli/cli) | `40b742f76d68e6b1f472942a6368db4b5d765641` | CI, dependency |
| [uv](https://github.com/astral-sh/uv) | `2a354c23dd9d86d13f081ee231cf99243b71849b` | CI, dependency |
| [Vite](https://github.com/vitejs/vite) | `ee644014aab61e546742b862a7d7b0d6c7d67a7b` | CI, dependency |
| [Immich](https://github.com/immich-app/immich) | `469a870a2233e7361bcb855b183fd41272cfd056` | CI, dependency, deployment, API |
| [Docker Awesome Compose](https://github.com/docker/awesome-compose) | `30f4b7f6a6c3b0c0ecf4d4efb0de203c48d11562` | deployment |
| [GitHub REST API description](https://github.com/github/rest-api-description) | `33c2d320fd411e9db6c8b68401e0ad2bdb0243fd` | API |

## CI workflow security

Write permissions observed in each repository were explicitly allowed for the calibrated pass. This isolates structural findings rather than pretending one organization's write allowlist applies globally.

| Repository | Workflows | Findings | Classification |
| --- | ---: | ---: | --- |
| GitHub CLI | 13 | 31 | 25 missing job timeouts, 1 mutable action, 5 implicit top-level permission sets |
| uv | 41 | 35 | 32 missing job timeouts, 3 implicit top-level permission sets |
| Vite | 13 | 35 | 18 missing job timeouts, 11 mutable actions, 6 implicit top-level permission sets |
| Immich | 27 | 69 | 66 missing job timeouts, 2 mutable actions, 3 implicit top-level permission sets |

Initial runs exposed three false-positive classes: reusable GitHub jobs were required to define a caller timeout, every `pull_request_target` trigger was rejected without an unsafe data flow, and GitLab jobs inheriting `default.timeout` were reported. The rule now exempts reusable callers, reports privileged pull requests only for untrusted checkout or direct script interpolation, and recognizes inherited GitLab timeouts. Every remaining finding is a direct syntactic policy discrepancy. Security impact still requires repository-owner review.

Decision: remain `experimental`. Finding volume needs owner triage and calibrated permission policy before `recommended`.

## Dependency governance

| Repository | Manifests | Findings after explicit policy calibration |
| --- | ---: | ---: |
| GitHub CLI | 2 | 0 |
| uv | 73 | 0 |
| Vite | 294 | 0 |
| Immich | 12 | 0 |

uv approved its actual dual-license expressions. Immich approved its actual AGPL expressions. Vite narrowly excluded `packages/vite/src/node/__tests__/plugins/fixtures/**`, which contains intentional license-parser fixtures; without that exclusion, the pack correctly reported CC0-1.0 and ISC against the default allowlist.

Initial runs exposed false positives for every nested Cargo or npm workspace manifest, unresolved-but-present workspace edges, and a real UTF-8-BOM package fixture that aborted evaluation. Ancestor workspace locks and repository-contained `workspace:`, `file:`, `link:`, and Cargo path targets are now resolved structurally; missing targets still fail. JSON accepts that BOM while retaining strict trailing-value checks.

Decision: remain `experimental`. Multi-repository signal is clean after explicit policy inputs, but repository owners have not reviewed false-negative coverage.

## Deployment invariants

| Repository | Compose inputs | Findings | Classification |
| --- | ---: | ---: | --- |
| Immich | 3 calibrated production/rootless files | 30 | 2 mutable images, 14 missing CPU/memory limits, 14 missing non-root/read-only declarations |
| Docker Awesome Compose | 39 | 141 | 45 mutable images, 2 unapproved registries, 47 missing limits, 47 missing runtime-security declarations |

The first Immich run exposed a false negative: root-only globs skipped nested Compose files. Root and nested discovery now share the rule, and `excluded_files` provides narrow reviewed exclusions. The calibrated Immich run excluded its development and E2E Compose files and allowed rendered image templates; mutable production tags remained visible. All final findings map to a concrete parsed service field.

Decision: remain `experimental`. Samples are intentionally permissive and produce high signal volume; production owners must decide which invariants apply.

## API contract hygiene

| Repository | Contract | Parsed operations | Result |
| --- | --- | ---: | --- |
| Immich | `open-api/immich-openapi-specs.json` | 275 | one expected `API consumption evidence is missing` warning |
| GitHub REST API | `descriptions/api.github.com/api.github.com.json` | 1,222 | one expected `API consumption evidence is missing` warning |

Both real OpenAPI contracts parsed successfully before the adapter failed closed on absent producer-owned consumption evidence. No synthetic evidence was created to turn contract enumeration into a false claim of client usage.

Decision: remain `experimental`. Real producer evidence from unrelated client implementations is still required for graduation.

## Artifact evidence

| Release | Evidence artifact digest | Subject digest | Producer | Result |
| --- | --- | --- | --- | --- |
| [Cosign v3.1.3](https://github.com/sigstore/cosign/releases/tag/v3.1.3), `cosign-linux-amd64_3.1.3_linux_amd64.sbom.json` | `sha256:d4a7d1a4f3cb5f4f87a01e81e511abb5f6f99c2e2bb7b929bde608a1ccfd14c3` | `sha256:4629c757b7618056f8ddd7e2625ae9fdd94c0372a65049520bc7d9df9efc7f71` | `syft-1.44.0` | pass, 0 findings |
| [GoReleaser v2.18.0](https://github.com/goreleaser/goreleaser/releases/tag/v2.18.0), `goreleaser_Linux_x86_64.tar.gz.sbom.json` | `sha256:f425858b59b08438d668427563eb7d0d18de2cbd49fb608ee01e37a56996e6e3` | `sha256:41cdf49b653784b03a08013dd99e382cd5d463049e915c2d818eaed182ae6197` | `syft-1.42.3` | pass, 0 findings |

The downloaded release assets were hashed independently. Both SPDX 2.3 documents use `SPDXRef-DOCUMENT DESCRIBES <subject>` relationships rather than `documentDescribes`. The first run rejected this valid representation; the adapter now supports both forms and still requires the described package or file SHA-256, exact evidence SHA-256, producer, timestamp, item threshold, and configured freshness.

Decision: remain `experimental`. SPDX/Syft interoperability is proven on two unrelated releases; equivalent real-world measurements remain needed for SARIF, CycloneDX, JUnit, and provenance before broader maturity.

## Reproduction pattern

```sh
git clone --depth=1 <source-url> measurement
git -C measurement checkout --detach <exact-revision>
mkdir -p measurement/.hoolicy-measure/packs
cp -R packs/<pack> measurement/.hoolicy-measure/packs/
hoolicy check --config hoolicy.measure.yaml --format json --output .hoolicy-measure/report.json
hoolicy pack verify packs/<pack>
```

Release-asset measurements replace the clone with downloads from the pinned release page, verify both SHA-256 values with `sha256sum`, move the large subject outside the evaluated directory, and evaluate only the pinned SBOM. Configuration uses a one-year freshness ceiling; it does not disable freshness.
