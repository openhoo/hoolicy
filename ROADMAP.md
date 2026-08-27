# Hoolicy roadmap

Hoolicy should make repository policy easier to adopt, author, distribute, and prove. It should not become a collection of fashionable checks or a second implementation of every scanner.

This roadmap is ordered by dependency and user value, not by calendar date. A milestone ships when its exit criteria are met. Minor releases may move individual items when real usage disproves the ordering.

## Product principles

1. **Useful signal over rule count.** Add a rule only when repository evidence can decide a meaningful risk or delivery invariant with low false-positive pressure.
2. **Adoption without hidden debt.** Existing findings may be ratcheted, but remain visible, attributable, and reviewable.
3. **Offline enforcement.** Network access stays confined to explicit acquisition and publication commands. `validate`, `check`, `test`, and `fix` remain offline.
4. **Policy is untrusted data.** No runtime plugins, shell expressions, or executable pack hooks.
5. **Evidence, not certification theatre.** Hoolicy may prove which checks ran against which inputs. A control mapping alone never means compliance.
6. **Safe change.** Automatic fixes remain previewed, hash-bound, deterministic, and opt-in.
7. **Interoperate before reimplementing.** Consume outputs from specialist tools where that is safer than building another vulnerability, secret, or license scanner.

## v0.2 — Adopt policy without stopping delivery

**Outcome:** a mature repository can introduce Hoolicy immediately, see all debt, and block only new regressions without maintaining a broad ignore file.

### Deliverables

- **Finding baseline and ratchet.** Add a reviewed baseline file containing stable finding fingerprints plus creation metadata. `check` still evaluates the complete repository, reports baseline findings separately, and fails on new or materially changed findings.
- **Git comparison mode.** Compare current policy decisions with a base Git revision. Do not merely scan changed files: cross-file and repository-wide rules must still run.
- **Baseline lifecycle.** Detect stale entries, changed policy digests, disappeared rules, and fingerprints that no longer reproduce. Provide an explicit prune command and a reviewable diff; never prune during `check`.
- **First-class CI summaries.** Emit concise pull-request summaries and GitLab Code Quality output while retaining SARIF and JUnit. Include rule, location, remediation, waiver state, and whether a finding is new or existing.
- **`hoolicy doctor`.** Diagnose config discovery, Git context, lock integrity, pack compatibility, ignored targets, unsupported file types, and CI base-revision detection without changing files.
- **Deterministic report comparison.** Add `hoolicy report diff` for JSON reports, keyed by fingerprints and policy digests.

### Exit criteria

- Full-repository evaluation catches a new cross-file violation even when only its source input changed.
- Baseline entries cannot weaken severity, hide configuration errors, or suppress a finding with a different fingerprint.
- Existing, new, fixed, waived, and stale findings are distinguishable in text and JSON reports.
- Baseline creation and pruning are preview-first and produce stable output across operating systems.
- GitHub Actions and GitLab CI examples cover pull requests, merge requests, default-branch scans, and shallow-clone failure messages.

### Not in this release

- Hosted finding triage.
- Silently changed-file-only evaluation.
- Importing old ignores without owner review.

## v0.3 — Make good policies easy to author

**Outcome:** pack authors get fast feedback about behavior, compatibility, and rule quality before a policy reaches a consuming repository.

### Deliverables

- **Pack scaffolding.** `hoolicy pack init` creates a manifest, schema references, documentation, and mandatory pass/fail fixtures.
- **Policy formatting and linting.** `hoolicy fmt` normalizes Hoolicy-owned YAML. `hoolicy lint` flags overbroad scopes, weak remediation, unused parameters, redundant rules, unsafe severity changes, and text checks better represented by structured kinds.
- **Precise fixture assertions.** Pack tests may assert rule ID, path, location, message fragments, semantic key, waiver behavior, and proposed fixes instead of only pass/fail.
- **Fixture contexts.** Tests can supply deterministic Git metadata, clock time, parameters, and multi-document files without invoking Git or the network.
- **Behavior snapshots.** A pack release can compare its findings against the previous release and produce a human-readable compatibility report. Updating snapshots is always explicit.
- **Compatibility declarations.** Packs declare supported Hoolicy config and engine ranges. Consumers fail with a clear error before evaluation.
- **Editor support.** Publish versioned JSON Schemas, YAML-language-server examples, shell completions, and machine-readable explain output. Defer a custom language server until schema support proves insufficient.

### Exit criteria

- A new pack can be scaffolded, tested, documented, and verified without copying files from another repository.
- Every official rule has positive, negative, malformed-input, and false-positive regression coverage where applicable.
- Compatibility reports expose added, removed, renamed, severity-changed, and behavior-changed rules.
- Lint findings explain their heuristic and can be disabled narrowly; heuristics never become blocking policy findings by accident.

## v0.4 — Distribute packs through a trust chain

**Outcome:** organizations can publish and consume policy packs at scale without executing remote code or trusting mutable Git references.

### Deliverables

- **OCI pack artifacts.** Add `hoolicy pack publish` and OCI acquisition with a dedicated media type. Lock files record registry, manifest digest, pack digest, and resolved release.
- **Signature verification.** Verify pack signatures against explicit local trust policy: allowed identities or keys, issuer constraints, and required signatures. Unsigned packs never become trusted implicitly.
- **Reproducible package format.** Canonical archive layout, normalized metadata, deterministic digest, size limits, path validation, and no symlinks or special files.
- **Publisher workflow.** Generate a release manifest, compatibility report, test result, and provenance reference before publication.
- **Organization catalogs.** Support a signed, static catalog of approved pack coordinates and versions. Catalogs recommend artifacts; lock files continue to select exact digests.
- **Safe update review.** `pack update` shows rule, severity, parameter, control mapping, and digest changes before writing vendor and lock data.

### Exit criteria

- Pulling by tag resolves once and checks by digest thereafter.
- Verification fails closed for wrong identity, wrong issuer, missing signature, digest mismatch, downgrade, or incompatible engine range.
- A vendored OCI pack produces the same active policy digest offline on Linux, macOS, and Windows.
- Pack publication cannot bypass its fixture suite or compatibility report.

### Not in this release

- Transitive pack dependencies.
- A public marketplace with rankings.
- Automatic trust based on registry hostname.

## v0.5 — Produce audit-ready decision evidence

**Outcome:** security and compliance teams can review what was enforced without treating screenshots, CI color, or control labels as proof.

### Deliverables

- **Evidence bundle.** `hoolicy evidence` records repository revision, dirty state, tool version, config digest, pack digests, evaluated rules, decision summary, waivers, timestamps, and referenced external evidence.
- **Control status model.** Report each mapped control as `passed`, `failed`, `waived`, `not-evaluated`, or `unmapped`. Keep rule results and control interpretation separate.
- **Evidence verification.** Verify bundle schema, subject revision, policy digests, signatures, and referenced artifact digests. Emitting provenance without verifying it is not sufficient.
- **External evidence adapters.** Read pinned local outputs such as SARIF, CycloneDX, SPDX, test reports, and provenance attestations. Enforce schema, subject, freshness, and threshold rules without running the producing scanner.
- **Decision attestation.** Optionally emit an in-toto-compatible signed statement binding the Hoolicy decision to its subjects and policy inputs.
- **Waiver review workflow.** Generate waiver templates from findings, require explicit approver metadata when configured, and show waiver additions, renewals, scope growth, and expirations in report diffs.

### Exit criteria

- A verifier can reproduce or reject an evidence bundle without access to the original CI user interface.
- Evidence fails verification when the source revision, config, pack, external report, or signature changes.
- Missing and stale external evidence fail closed according to declared policy.
- Documentation states exactly what Hoolicy proves and what remains an organizational judgment.

## v0.6 — Scale across monorepos and policy estates

**Outcome:** large repositories and organizations get faster feedback without ambiguous inheritance or weakened repository-wide rules.

### Deliverables

- **Explicit workspace scopes.** One root policy may define named project scopes, owned paths, parameters, and applicable packs. No implicit directory inheritance.
- **Dependency-aware incremental evaluation.** Cache parsed documents and rule inputs, invalidate by content and policy digest, and expand changes through declared cross-file dependencies.
- **Ownership routing.** Map findings to repository-owned team identifiers or CODEOWNERS-derived ownership while keeping enforcement independent from notification delivery.
- **Policy inventory.** Produce a machine-readable inventory across workspace scopes: active rules, versions, controls, waivers, owners, and policy digests.
- **Resource budgets.** Per-rule timing, input counts, CEL cost, cache hits, and hard limits for files, document sizes, findings, and total execution time.
- **Read-only service mode.** Optional local daemon for editor and CI reuse of parsed state. Same engine, same digests, no remote policy execution, no mutation API.

### Exit criteria

- Incremental and clean full runs produce identical findings and fingerprints.
- Scope overlap, unowned paths, cyclic dependencies, and conflicting parameters fail during validation.
- Benchmarks cover small repositories, large monorepos, and adversarial input limits.
- Service mode can be disabled without losing functionality or report compatibility.

## v1.0 — Stable contract

**Outcome:** teams can standardize on Hoolicy with a documented compatibility, security, and migration promise.

### Deliverables

- Stable config, lock, baseline, pack, evidence, JSON report, exit-code, and Go SDK contracts.
- Automated migration command for every supported on-disk format change.
- Published deprecation policy and minimum support window.
- Independent threat-model review and fixes for pack acquisition, path handling, parsers, CEL limits, report generation, and safe fixes.
- Reproducibility, performance, and cross-platform release gates.
- Recovery documentation for bad pack releases, compromised publisher identities, corrupt baselines, and failed fix application.

### Exit criteria

- Compatibility suite exercises upgrades from every supported minor line.
- Golden reports and policy digests match across supported platforms.
- No unresolved critical security findings or undocumented trust boundary.
- SDK examples compile against the release and its declared compatibility range.

## Curated rule-pack track

Engine releases should not wait for every official pack. Packs graduate independently through `experimental`, `recommended`, and `stable` maturity levels.

### Highest-value next packs

1. **CI workflow security.** Parse GitHub Actions and GitLab CI for mutable third-party actions/includes, excessive token permissions, unsafe fork or `pull_request_target` use, untrusted script interpolation, and missing job timeouts. Keep vendor behavior in separate rules.
2. **Artifact evidence.** Require locally available SBOM/provenance/test artifacts to match the built subject, schema, producer, and freshness policy. Do not generate fake evidence from file presence.
3. **Dependency governance.** Parse ecosystem manifests and lockfiles for missing locks, source drift, unresolved local references, and policy-approved license expressions. Delegate vulnerability discovery to dedicated scanners.
4. **Deployment invariants.** Structured checks for Kubernetes, Helm, Compose, and Terraform evidence: immutable images, resource limits, explicit security context, environment separation, and approved sources. Every opinion must be parameterized or tied to a documented risk.
5. **API contract hygiene.** Compare OpenAPI operations and schema properties with generated clients or declared consumption evidence. Start experimental because language-aware usage analysis has high false-positive risk.

### Graduation gates

- Real incident, control, or delivery-risk rationale; no style-only rule.
- Maintained parser or documented schema; regex only for narrow literals.
- Positive, negative, malformed, and known-false-positive fixtures.
- Measured results on multiple unrelated repositories.
- Clear ownership, remediation, waiver scope, and compatibility notes.
- Removal when the compiler, platform, or specialist scanner provides a better authoritative check.

## Explicit non-goals

- Runtime executable plugins or scripts in packs.
- A general-purpose CI engine, vulnerability scanner, secret scanner, test runner, or package manager.
- Compliance certification from a passing command.
- Opaque AI-generated policies or automatic severity decisions.
- A hosted dashboard before local reports, evidence, and VCS review workflows are complete.
- Automatic mass fixes without a reviewed, hash-bound plan.
- Rule-count goals, gamified compliance scores, or checks that reward adding meaningless files and tags.

## Design signals

The sequence incorporates useful patterns from adjacent tools without copying their trust model:

- [Semgrep documents diff-aware scans](https://semgrep.dev/docs/semgrep-ci/findings-ci) that show findings relative to a baseline. Hoolicy should adopt the regression-focused workflow, but retain full evaluation so repository-wide invariants are not skipped.
- [Open Policy Agent supports signed bundles](https://www.openpolicyagent.org/docs/management-bundles) to establish policy origin and integrity. Hoolicy should make verification policy explicit and fail closed.
- [ORAS distributes arbitrary OCI artifacts](https://oras.land/docs/concepts/artifact/) through existing registries. That makes OCI a better pack transport than inventing a Hoolicy-specific registry protocol.
- [SLSA separates provenance from verification](https://slsa.dev/spec/v1.0/verifying-artifacts). Hoolicy evidence must therefore include a verification workflow, not only another generated document.

## How priorities change

Move an item earlier only when it removes a demonstrated adoption blocker, prevents a real false negative, or closes a trust boundary. Move it later when it adds hidden state, requires a hosted control plane, duplicates a stronger specialist tool, or cannot state objective exit criteria.
