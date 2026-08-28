# Roadmap implementation status

Status date: 2026-08-28. Repository implementation covers the roadmap through the v1 contract. This is not a declaration that `v1.0.0` has been released.

## Repository-complete milestones

- **v0.2 adoption:** exact finding baselines and ratchets, full-tree Git comparison, preview-first create/prune lifecycle, GitHub and GitLab summaries, `doctor`, deterministic report diff, and shallow-clone CI examples.
- **v0.3 authoring:** pack scaffold, deterministic formatter, advisory lint, precise fixtures and contexts, reviewed behavior snapshots, pack comparison, compatibility ranges, versioned schemas, completion scripts, and machine-readable explain output.
- **v0.4 distribution:** deterministic bounded pack archives, Git and signed OCI acquisition, explicit key or identity-plus-issuer trust, immutable digest locks, release manifests, preview-first updates, and signed static catalogs.
- **v0.5 evidence:** schema-backed decision bundles, reproduction verification, separate control states, field-specific SARIF, CycloneDX, SPDX, JUnit, and in-toto adapters, optional Cosign decision attestations, and exact waiver review diffs.
- **v0.6 scale:** explicit non-inherited workspaces, ownership and dependency validation, content-and-policy-bound input and parse caches, inventory output, hard resource budgets, and loopback GET-only service mode.
- **v1 contract:** report migration, an explicit `v0.1.x` input-compatibility fixture, compatibility and deprecation promise, immutable `schemas/v1` copies, compiling SDK example, cross-platform golden output, race and performance gates, reproducible release archives, threat-boundary record, and recovery procedures.
- **Curated packs:** CI workflow security, artifact evidence, dependency governance, deployment invariants, and API contract hygiene exist with structured parsers and positive, negative, malformed, and false-positive fixtures where applicable. Reproducible multi-repository results and the resulting parser fixes are recorded in [pack measurements](pack-measurements.md).

## Executable release evidence

CI runs the Go suite on Linux, macOS, and Windows. Quality CI also runs formatting and module-drift checks, `go vet`, the race detector, stable-contract golden tests, small/medium/large/adversarial benchmarks, every pack's fixtures, digest verification, reviewed snapshot comparison and lint, repository dogfooding, JSON syntax checks, deterministic archive reproduction, and a container build.

Release CI reruns tests and pack qualification at the release tag, builds deterministic archives, creates an SPDX SBOM, signs and attests release assets, publishes a provenance-enabled multi-platform image, and signs its immutable digest.

## Gates outside this working tree

These gates cannot be self-certified by the implementation author:

1. An independent reviewer must use the [threat-review packet](threat-review-checklist.md) to review pack acquisition, path handling, parsers, CEL limits, reports, evidence, and safe fixes; findings must be recorded and resolved before declaring the roadmap's independent v1 threat-model criterion complete.
2. New official packs remain `experimental` until owners accept the recorded multi-repository results, complete repository-specific false-negative review, and approve graduation. Measurement alone does not justify `recommended`.
3. Publication requires an authorized commit, remote CI success, release tag, artifact/signature readback, and image-digest verification. Current published version remains the value in `VERSION` until that chain completes.

No local command, green unit test, or document may replace these external gates.
