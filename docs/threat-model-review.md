# Threat-model review record

Review scope covers untrusted configuration and packs, Git and filesystem discovery, OCI acquisition, archive extraction, document parsers, CEL, reports, evidence, and safe fixes. This record is evidence for repository review; release owners should still seek a reviewer who did not author the implementation before declaring an external independent assessment.

| Boundary | Abuse case | Enforced control | Regression evidence |
| --- | --- | --- | --- |
| Paths | traversal, absolute path, symlink escape, special file | repository-relative validation, component-wise `Lstat`, regular-file checks | `internal/safepath`, repository, fix, archive tests |
| Pack archive | traversal, duplicate name, decompression or file-count abuse | canonical tar, fixed metadata, no links/special files, byte/file limits | `internal/packarchive` tests |
| OCI trust | mutable tag, unsigned artifact, wrong key/identity/issuer, media-type confusion, downgrade | resolve once, digest pull, exact artifact and layer media types, explicit trust rule, Cosign verification, pre-install compatibility and downgrade checks | `internal/ocipack` and pack tests |
| Parsers | duplicate keys, trailing documents, malformed structured input, huge file | strict YAML/JSON, duplicate-key rejection, parser errors fail closed, document budget | config, document, engine tests |
| CEL | code execution or resource exhaustion | fixed variables, no host functions, compile-time static check, hard cost ceiling, rule/total timeout | CEL and engine tests |
| Reports | terminal injection, ambiguous finding identity, waiver hiding | control-character stripping, digest-bound fingerprints, exact waiver and baseline validation | report, SDK, engine tests |
| Evidence | stale or unrelated scanner artifact, changed inputs, forged signature | exact artifact/subject digests, freshness/thresholds, decision reproduction, exact key or identity plus issuer | evidence and OCI tests |
| Fixes and pack updates | stale bytes, dirty target, overlapping edits, downgrade, partial apply | preview, expected SHA-256, clean/symlink checks, staged writes, pre-install downgrade rejection, transactional vendor/lock rollback | fix and pack tests |

No policy-controlled runtime plugin, process execution, network request, or mutation endpoint exists. Explicit acquisition/publication and Cosign/ORAS invocation are command-owned operations, never evaluation hooks.

Residual boundary: a hostile process running as the same operating-system user can race filesystem operations between checks. Hoolicy revalidates each component and target immediately before staged replacement, rejects symbolic links and non-regular inputs, and never treats this as isolation from a compromised local account. A crash between atomic renames can leave a `.hoolicy-backup-*` file; recovery steps are documented. Compile-time SDK rule extensions are trusted Go code and must honor context cancellation; built-in rules are data-only and bounded. This record is an internal review, not the independent v1 review required by the roadmap. The independent reviewer must use the [review packet](threat-review-checklist.md) and publish a revision-bound finding record.
