# Independent threat-model review packet

This packet is for a reviewer who did not author the reviewed implementation. Completing it is mandatory before the v1 independent-review criterion may be marked complete. Repository authors must not fill the reviewer decision or close their own findings.

## Review identity

Copy this section into `docs/reviews/YYYY-MM-DD-v1-threat-model.md` and replace every placeholder.

```text
Reviewer: <name or accountable identity>
Affiliation: <organization or independent>
Independence statement: <relationship to implementation authors>
Review started: <RFC3339>
Review completed: <RFC3339>
Reviewed Git revision: <full 40-hex commit>
Reviewed Hoolicy version: <semantic version>
Outcome: accepted | rejected | accepted-with-resolved-findings
Unresolved critical findings: <integer>
Unresolved high findings: <integer>
```

The reviewed revision must be immutable and remotely available. Record later fix commits per finding. Review all fixes and identify the final accepted revision explicitly; a review of an earlier tree does not automatically cover later code.

## Required qualification

Run from a clean checkout of the exact reviewed revision. Preserve complete logs as review evidence.

```sh
git status --short
git rev-parse HEAD
go version
go test ./... -count=1
go test -race ./... -count=1
go vet ./...
go test ./internal/engine -run 'TestCrossPlatformGoldenReportAndPolicyDigest|TestResourceBudgetsFailClosed|TestRuleTimeoutIsEnforced' -count=1
go test ./internal/packarchive ./internal/ocipack ./internal/packs ./internal/safepath ./internal/fix ./internal/evidence ./internal/document ./internal/report -count=1
for pack in packs/*; do go run ./cmd/hoolicy pack verify "$pack"; go run ./cmd/hoolicy pack snapshot "$pack"; go run ./cmd/hoolicy lint "$pack"; done
scripts/verify-reproducible.sh
```

Also inspect remote Linux, macOS, and Windows CI for the exact revision. Local success is not cross-platform evidence.

## Boundary checklist

For each boundary, inspect code and tests, exercise at least one original adversarial case, and record `accepted`, `finding <ID>`, or `not covered`. `not covered` prevents acceptance.

### Pack acquisition and publication

- Mutable tag resolves once; every later ORAS and Cosign operation uses the resolved digest.
- Exact pack or catalog artifact type and complete layer-media-type set are checked before extraction.
- Key mode and identity-plus-issuer mode fail closed for no match, malformed verifier output, missing signature, wrong identity, and wrong issuer.
- Release manifest binds pack digest, identity, release, maturity, owner, compatibility notes, test result, compatibility report, and immutable provenance.
- Archive rejects traversal, duplicate paths, non-canonical metadata, links, special files, excessive files, and excessive expanded bytes.
- Compatibility and downgrade checks happen before vendor installation.
- Multi-pack vendor and lock update rolls back on acquisition, installation, or lock-commit failure.
- Publication cannot skip fixtures, lint, reviewed snapshot, compatibility output, provenance, or signing.

Primary entry points: `internal/ocipack`, `internal/packarchive`, `internal/packs`, and `application.packPublish` in `internal/cli`.

### Repository and path handling

- Absolute, parent, backslash, drive-letter, UNC, NUL, and non-portable paths fail.
- Every policy-controlled existing or writable path rejects symlinked parents and final targets.
- Repository discovery does not follow links or read outside the root.
- Git subprocess arguments cannot become options through a revision, ref, path, or URL field.
- Opened-file identity and size are rechecked where a hostile same-user race is relevant.

Primary entry points: `internal/safepath`, `internal/repository`, config path validators, report output, evidence input, and fix application.

### Parsers and untrusted policy

- Strict YAML rejects duplicate keys and unknown fields; JSON/XML reject trailing values or roots.
- Malformed matched input fails closed and cannot count as a negative fixture.
- Size and count limits apply before or during parsing.
- Pack parameter expansion preserves types, cannot introduce executable behavior, and cannot escape list structure unexpectedly.
- SARIF, CycloneDX, SPDX, JUnit, and in-toto adapters read only defined subject, producer, timestamp, and result fields.
- SPDX direct and relationship-based described subjects remain exact-digest bound.

Primary entry points: `internal/config`, `internal/document`, `internal/policytest`, and `internal/evidence`.

### CEL and evaluation limits

- CEL has fixed variables and no host process, filesystem, network, clock, or nondeterministic functions.
- Compile errors fail validation before evaluation.
- Static or runtime cost, per-rule duration, total duration, file count, document bytes, and finding limits fail closed.
- A compile-time custom rule that ignores context cannot prevent the engine timeout from returning.
- Clean and cached runs produce identical findings and fingerprints.

Primary entry points: `internal/rules`, `internal/engine`, and `internal/repository` caches.

### Reports, baselines, waivers, and evidence

- Finding fingerprint and policy/finding digests bind all decision-relevant identity.
- Baseline accepts only exact reviewed fingerprints and cannot lower severity or hide config/parser failures.
- Waivers require bounded exact scope, ownership, ticket, dates, and configured approver; expired or enlarged scope stays reviewable.
- Text, GitHub, GitLab, JUnit, SARIF, and JSON outputs escape or strip control and markup injection as appropriate.
- GitHub and GitLab output retains state, location, remediation, and waiver identity.
- Evidence verification recomputes decision inputs and rejects changed repository revision, config, pack, external artifact, subject, or signature.
- Failed attestation signing publishes neither final statement nor final signature bundle.

Primary entry points: `sdk`, `internal/engine`, `internal/report`, `internal/evidence`, and evidence/waiver CLI paths.

### Safe fixes and local service

- Fix preview binds existence and old SHA-256, rejects dirty or symbolic targets, rejects overlap, and applies atomically.
- Multi-file failure restores earlier files; crash recovery artifacts are documented.
- Service binds loopback only, exposes GET/read-only routes only, uses the same engine and report contract, and has bounded server timeouts.
- No validation, check, test, fix, report, inventory, migration, or service request can acquire policy or invoke pack-controlled processes.

Primary entry points: `internal/fix`, `application.serve`, and command dispatch.

## Required original attack cases

The reviewer must add or preserve regression tests for any successful attack. At minimum attempt:

1. OCI manifest with valid signature but wrong artifact type, one duplicate expected layer, and one omitted expected layer.
2. Downgrade whose acquisition succeeds but must leave vendor and lock byte-identical.
3. Archive containing duplicate normalized paths and a symlink or traversal target.
4. Writable output whose parent becomes a symlink between preview and application.
5. Structured input with duplicate YAML key, multiple JSON values, oversized document, and valid UTF-8 BOM followed by trailing JSON.
6. CEL expression near the cost ceiling and a custom rule that ignores cancellation.
7. Report fields containing ANSI control bytes, HTML, Markdown delimiters, credentials, and multiline content.
8. SPDX relationship that describes a subject with the wrong checksum while another unrelated package contains the expected checksum.
9. Evidence statement and signature bundle where signing fails after temporary output creation.
10. Read-only service request using non-loopback bind, non-GET method, path traversal, and oversized input repository.

## Finding record

Use one row per finding. Do not erase rejected or resolved findings.

| ID | Severity | Boundary | Attack or evidence | Required fix | Fix revision | Reviewer retest | Status |
| --- | --- | --- | --- | --- | --- | --- | --- |
| `<review-id>` | critical/high/medium/low/info | `<boundary>` | `<reproduction>` | `<acceptance condition>` | `<commit>` | `<result and date>` | open/resolved/accepted-risk |

Accepted risk requires named owner, rationale, expiry, and external tracking link. Critical findings cannot be accepted. High findings block v1 unless the independent reviewer explicitly documents why the severity was reduced after retest.

## Acceptance statement

The independent reviewer may accept only when:

- every checklist item has evidence;
- every original attack case has a recorded result;
- every critical and high finding is resolved and retested;
- no trust boundary remains undocumented;
- the final accepted revision passes local gates and remote cross-platform CI;
- the record states what was not proven, including same-user host compromise and organizational compliance judgment.

The release owner then links the completed record from release notes. This template, the internal threat record, or a green pipeline alone is not independent review.
