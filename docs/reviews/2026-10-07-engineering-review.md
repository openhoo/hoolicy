# Hoolicy engineering review — October 7, 2026

## Scope and method

Four agents reviewed Hoolicy together. Three agents focused on core rules and
the SDK, security and integrity boundaries, and CLI/reporting/adoption workflows.
The coordinator reviewed installation, integrated changes, and ran qualification.
The agents also cross-reviewed one another's fixes. The checkout started clean
at `0a235d78a3d294f079f0eae9ff01f4c5ed02b7d0` (the `v0.4.1` release), matching `origin/main` when fetched during
the review. Changes are on `fix/hoolicy-review-polish-20261007`.

This is an engineering review with targeted adversarial regressions. It does
not satisfy the independent external reviewer requirement in
`docs/threat-review-checklist.md` or certify organizational compliance.

## Resolved findings

| ID | Area | Finding and correction |
| --- | --- | --- |
| HLC-01 | Manifest fixes | Regex value matching could edit a sibling key or only the numeric prefix of a larger token. Follow the exact JSON pointer and decoder byte offsets, verify the old scalar value, and retain BOM offsets. |
| HLC-02 | Translation catalogs | Literal dotted keys and nested keys could overwrite the same flattened key nondeterministically. Traverse deterministically and reject ambiguous catalog keys. |
| HLC-03 | Dependency governance | Block-form and quoted Go `replace` directives escaped local replacement checks. Parse these forms, retain source line locations, and reject malformed or unclosed replacements. Add passing and failing pack fixtures. |
| HLC-04 | SDK disposition | Rule output could arrive already marked waived or accepted. Finalization now clears unverified waiver and baseline disposition before the engine applies reviewed state. |
| HLC-05 | SDK registration | A typed nil implementation could pass interface validation and panic during evaluation. Reject nil implementations at registration. |
| HLC-06 | Pack digests | NUL-containing file bytes could reproduce the separators of a different file tree. Reject those bytes; existing ordinary text pack digest values remain unchanged. |
| HLC-07 | Pack updates | Staged pack bytes and writable destination parents could change after preview. Rehash staged trees and revalidate vendor, removal, and lock paths before mutation. |
| HLC-08 | Safe fixes | Temporary replacement bytes or their file type could change before installation. Retain the reviewed replacement and verify the staged regular file immediately before installation. |
| HLC-09 | JUnit evidence | Trailing roots, understated root/suite counts, and unsupported nested suites could conceal failures. Require one root, reject unsupported placement/nesting, and compare summary counts with child suites and present testcase results. |
| HLC-10 | Preview safety | Several commands could persist changes after failing to display their preview. Gate waiver, baseline, migration, pack update, and formatting writes on successful output, including short writes. Migration apply now displays the complete migrated report. |
| HLC-11 | Credential diagnostics | Only the first credential URL was redacted from a diagnostic. Redact all credential URLs in CLI, Git pack, and OCI output. |
| HLC-12 | Report rendering | Untrusted metadata could emit terminal controls or active Markdown. Sanitize text/diff metadata and operational errors; render links, images, and backticks literally in GitHub summaries. Preserve machine report data and byte-accurate unified patches. |
| HLC-13 | Release installer | Substring matching accepted a version prefix, such as `0.4.10` for `0.4.1`. Check the exact reported version, validate semantic version identifiers, and clean temporary files after success or failure. |
| HLC-14 | Pack fixture matching | A broad expected finding could consume the only match for a later specific expectation. Use distinct matching with reassignment so valid results do not depend on expectation order. |

## Usability and developer polish

- Completion help succeeds for `-h`, `--help`, and `help`.
- Pack update examples show preview followed by explicit `--apply`.
- Documentation explains option placement, failed-preview behavior, pack
  restrictions, and JUnit evidence validation.
- Temporary Git fixture commands disable signing per command, so contributor
  signing-agent availability does not affect tests. Repository and global
  signing configuration remain unchanged.
- The unreadable-index fixture checks whether the host actually enforces its
  file permissions; privileged users skip a precondition they cannot reproduce.
- Versioned schemas and historical compatibility fixtures remain unchanged.

## Verification

Qualification logs are stored outside the repository at
`/Users/wakemeup/.codex/artifacts/hoolicy-review-20261007/`.

The review exercises full package tests, race checks, vet, all eight policy
packs, stable-contract golden tests, engine benchmark smoke tests, installer
fixtures, and a container build with read-only repository evaluation. Linux
qualification uses the repository's pinned Go 1.26.6 Alpine image with Git and
the GNU archive tools required by the release scripts.

| Check | Result |
| --- | --- |
| macOS Go 1.27.1, `go test ./... -count=1` | Passed |
| macOS Go 1.27.1, `go test -race ./... -count=1` | Passed |
| `go vet ./...` and `git diff --check` | Passed |
| All eight pack suites | 82/82 cases passed |
| All pack verification, behavior snapshots, and lint | Passed; zero lint findings |
| SDK stable-contract golden digests | Passed |
| Engine small/large/adversarial benchmark smoke tests | Passed; no comparative performance claim |
| Linux Go 1.26.6 full tests, unprivileged user | Passed |
| Five platform release archives built twice | Byte-for-byte reproducible in qualification mode |
| Final scratch container build | Passed with the pinned Go 1.26.6 builder |
| Final container `version`, `validate`, and read-only `check` | Passed; four active rules and zero findings |

Native Windows execution and release signature/publication verification must
be provided by their corresponding CI and release workflows. The installer
regressions use local download fixtures and a stub signature verifier; they
verify archive/checksum/version handling, not the Sigstore trust service.

Filesystem revalidation reduces concrete preview-to-apply tampering risks; it
does not establish protection against arbitrary compromise by the same host
user. JUnit summaries are checked for consistency with results that are
present; count-only producers retain support, and metadata alone cannot prove
that an external test actually ran.
