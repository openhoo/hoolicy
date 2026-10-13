# Hoolicy multi-agent smoke testing — October 13, 2026

## Scope

Four agents exercised the current `feat/more-rule-packs` integration branch:
the coordinator and three owners for CEL/parsing, packs/fixtures, and CLI/file
safety. The starting checkout was clean at
`3c300e76f72d` (the complete SHA is recorded in `base-sha.txt`).
The work qualifies local source changes and local binaries/containers.

The initial `go test ./...` suite passed. Subsequent adversarial tests found
the defects below, with failing reproductions saved before correction.
Owners reviewed each other's changes before the final qualification.
A fifth agent independently reviewed the final evidence path corrections and
reproduced HSM-20. Its saved failure and the subsequent successful alias checks
are retained in `final-evidence-review.md`.

## Corrections

| ID | Reproduced failure | Correction and regression boundary |
| --- | --- | --- |
| HSM-01 | Nested CEL equality, inequality and membership performed about 1.2 million comparisons while charging roughly 18,000 under a 100,000 limit. | Bound structural comparison inside each call and charge its traversal against the cumulative evaluation budget. |
| HSM-02 | Nested `distinct()` performed about four million comparisons and passed a one-million cost limit. | Bound nested comparisons before dispatch and account for their cumulative cost. |
| HSM-03 | `flatten(2)` visited 1.2 million empty containers in about 2.22 seconds and passed; empty-container formatting also bypassed its traversal guard. | Count container visits, including empty lists/maps, before extension work and in flatten accounting. |
| HSM-04 | A public format containing the private cache delimiter selected lenient YAML or preserved-number cache entries. | Typed cache keys separate path, canonical format, digest, and parser mode. Strict inputs cannot select foreign syntax-node caches. |
| HSM-05 | A canceled CEL context evaluating literal `true` passed. | Check cancellation before preparation, during parsing/result conversion, and after evaluation. |
| HSM-06 | Uppercase `AUTO` parsing depended on whether its cache was warm. | Canonicalize formats before both parsing and cache selection. |
| HSM-07 | The precise JSON cache regression failed with `-count=2` because its path was shared across runs. | Use unique temporary paths and verify repeated execution. This is a test-isolation correction. |
| HSM-08 | Privileged workflow checkout missed constant bracket property access. | Recognize dot and single-quoted bracket access, including mixed access forms. |
| HSM-09 | Quoted guard text, negated comparisons and arbitrary OR alternatives exempted privileged checkout. | Require a constrained mandatory positive guard; retain the documented guarded workflow-run/dispatch form. |
| HSM-10 | Literal branch names and quoted expression/function arguments containing GitHub context text produced findings. | Distinguish literal text from supported real context references; retain detection after quoted arguments. |
| HSM-11 | Invalid fixture paths or setup collisions could become passing `outcome: error` tests. | Validate canonical, case-portable, noncolliding fixture paths and reserved metadata before evaluating expected errors. Include file ancestors, aliases and cross-map overlaps. |
| HSM-12 | A dirty literal `:(literal)a.txt` evaded Git status; bracket names matched unrelated dirty paths. | Use literal Git pathspecs when checking fix targets. Test both false negatives and false positives with actual Git. |
| HSM-13 | A `files.create` policy made `fix --apply` write `.git/info/attributes`. | Reject Git metadata during plan building and application, including nested components, aliases and metadata-root projects. |
| HSM-14 | OCI manifests, signed pack release manifests and decision attestations accepted duplicate JSON keys. | Use the shared strict JSON parser before typed decoding; reject ordinary, escaped-equivalent and nested duplicates. |
| HSM-15 | Evidence creation on clean source succeeded, then immediately failed verification because its unignored output dirtied source. | Preflight every artifact destination before mutation and recheck after evaluation. Protect policy inputs, pack content, metadata, aliases and actual linked/separate Git directories. |
| HSM-16 | Resource validation accepted `1bogus`, `1GiJUNK` and incomplete exponents, and rejected valid Kubernetes `+1`. | Validate complete platform-specific quantities. Compose CPU values cannot use Kubernetes millicore suffixes. |
| HSM-17 | Ordinary numeric Compose YAML CPU/memory limits were discarded during string conversion. | Preserve raw numeric values at both service and nested deployment resource locations. |
| HSM-18 | Compose memory `1e-3` passed despite truncating to zero bytes and disappearing from actual Compose configuration. | Require at least one effective byte after unit conversion. Test numeric and string forms. |
| HSM-19 | An evidence bundle, statement or signature path could also be another artifact's parent directory; the command left partial files/directories before failing. | Reject ancestor/descendant artifact paths during preflight. Actual CLI regressions assert all three parent roles fail before creating any artifact or parent. |
| HSM-20 | A dangling parent symlink hid an artifact overlap from both preflights and left a partial evidence bundle. | Distinguish an existing dangling symlink from absent parents during canonicalization and reject it. Preserve resolvable aliases; test direct and nested missing descendants and the CLI no-write boundary. |

The guarded CEL implementation is compared with native CEL behavior for
numeric/byte/null equality, wrong overloads, dynamic membership, and nested or
top-level errors/unknowns. Shared compiled programs are exercised concurrently;
comparison counters are local to each invocation.

## Qualification

| Surface | Result |
| --- | --- |
| CI-pinned toolchain | Go 1.26.6 |
| Full ordinary and race suites | Passed; 292 top-level tests and 327 subtests per suite across 21 tested packages; two packages contain no tests |
| Vet, formatting and diff whitespace | Passed |
| Stable SDK digests, immutable versioned schemas and compatibility tests | Passed |
| Core repeated execution | `-count=2` passed |
| JSON fuzzing | 276,100 executions in a bounded 20-second, two-worker run |
| Shared CEL program reuse | 24 workers × 10 evaluations passed |
| All 15 packs | 305/305 fixtures; all 45 verify/snapshot/lint commands passed |
| Actions and Kubernetes hardening | 74/74 and 69/69 fixtures; synchronized examples and snapshots |
| Additional pack fixtures | 36 added: 29 workflow/Kubernetes boundaries and 7 resource cases |
| Checked-in consumer examples | Actions, Kubernetes, structured configuration and repository policy passed |
| Broad compiled-binary CLI/service session | 167/167 checks plus 4/4 artifact layout subprocess regressions passed |
| Coordinator native consumer matrix | 53/53 checks passed |
| Actual service | 36 concurrent requests and five non-GET refusals passed |
| Offline pack use | Acquire a synthetic Git pack, delete its remote, check offline, then reject vendor tampering |
| Cross builds | Darwin amd64/arm64, Linux amd64/arm64 and Windows amd64 passed |
| Source containers | Linux arm64 and amd64 built from the final patched source; 53/53 consumer checks per image, network disabled and caller UID/GID; read-only repository dogfood also passed |

The CLI session covers eight starter profiles, six report formats, output
errors, fix preview/application, dirty/staged/symlink refusal, baselines,
waivers, evidence drift, pack acquisition and service behavior. The coordinator
matrix independently checks the reports and resource corrections with actual
process exit codes and parsed output.

The final implementation was frozen before these gates and checked again
afterward using `implementation-hashes-final-start.json` and
`frozen-implementation-verification.json`. Full suite execution is sequential
with `GOMAXPROCS=2`, `-p=1`, and `-parallel=1`. Earlier overlapping runs exceeded
wall-time assertions or the five-minute pack-suite timeout. Their failed logs
are retained; production cost/time limits and test timing assertions were not
relaxed. Shared CEL program reuse and the actual HTTP service retain explicit
concurrent tests.

## Evidence output behavior

An output inside the enclosing Git repository must be untracked and Git
ignored. Otherwise choose an output outside that repository. Plain source
trees and environments without Git require external outputs. The default
filename is preserved, with its ignore requirement documented in
`docs/evidence.md`. Artifact generation preserves revision, dirty-state,
policy-input and decision verification. It does not silently exclude inputs.

## Evidence and practical limits

Receipts and repeatable harnesses live in the local artifact directory
`hoolicy-smoke-20261013` under the operator's Codex artifacts. Its index files
are `session-summary.json`, `qualification-summary.json`, `all-pack-fixtures.json`,
`core/REPORT.md`, `packs/summary.json`, and `cli/subprocess-summary.json`.
Native binaries, container identifiers, source-file hashes and the complete
patch are also retained there. The final gate index is
`complete-gate-results.json`; container results are in
`complete-container-results.json`. The complete patch includes new files as
well as tracked modifications.

Initial rapid-edit container runs reported inconsistent policy size through
the macOS bind mount and returned operational exit 2. Host-side snapshot runs
subsequently exceeded the harness's 20-second container startup/execution
timeout. The failed receipts are retained. Final container qualification
copies each fixture tree into the scratch container's private Linux filesystem,
including caller-owned directory metadata, and gives the harness 120 seconds
for container creation/copy/startup. The Hoolicy binary's input-consistency
validation and production limits remain strict. These passing checks qualify
private-filesystem execution; rapid host rewrite/bind-mount metadata behavior
is an environment limitation, rather than a claimed product correction.

Registry/signature tests use local fake tools and do not establish public
registry publication or live signing-service behavior. Linux amd64 container
execution uses Docker's architecture emulation on this arm64 host. Windows and
Darwin amd64 are compile checks rather than native execution. Versioned schemas
are unchanged. Experimental pack guards remain conservative literal-document
analysis; unsupported conditional forms require policy-owner review. Resource
checks do not replace deployment schema validation or capacity planning.

Artifact preflight does not lock the filesystem against unrelated writers.
Structural cost accounting adds a second bounded traversal to retain shared
cost tracking; the benchmark receipts are one-iteration qualification checks,
not a performance trend study.
