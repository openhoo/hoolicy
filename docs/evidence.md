# Decision evidence

`hoolicy evidence` evaluates the full repository and writes a deterministic evidence bundle. `hoolicy evidence verify` reloads current local inputs and rejects a bundle when repository revision or dirty state, configuration, active rules, pack lock, waivers, findings, controls, or pinned external evidence no longer match.

```sh
mkdir -p ../hoolicy-artifacts
hoolicy evidence --output ../hoolicy-artifacts/hoolicy-evidence.json
hoolicy evidence verify ../hoolicy-artifacts/hoolicy-evidence.json
```

Choose an output outside the enclosing Git repository, or an untracked path
already excluded by Git ignore rules. Writing an unignored artifact would
change the evaluated source or repository dirty state and make its own evidence
unverifiable. Hoolicy preflights every output before creating files or parent
directories and returns exit code `2` with an actionable path suggestion when
the output is unsafe. A tracked output remains unsafe even when an ignore rule
matches it. Policy inputs, policy pack content, Git metadata, symlink files,
and overlapping output paths are rejected. An artifact path cannot also be a
parent directory for another artifact. Existing dangling parent symlinks are
rejected; resolvable parent aliases use their physical paths. Hoolicy does not
edit `.gitignore`.

The default filename remains `hoolicy-evidence.json`; explicitly ignore that
untracked path before using the default. If Git is unavailable, choose an output
outside the repository root so ignore status does not need verification. For
source trees without Git metadata, outputs must also be outside the source root.

Optional decision signing uses an in-toto Statement and a Cosign verification bundle:

```sh
hoolicy evidence --output ../hoolicy-artifacts/hoolicy-evidence.json \
  --attestation ../hoolicy-artifacts/decision.intoto.json \
  --signature-bundle ../hoolicy-artifacts/decision.sigstore.json \
  --sign-key cosign.key

hoolicy evidence verify ../hoolicy-artifacts/hoolicy-evidence.json \
  --attestation ../hoolicy-artifacts/decision.intoto.json \
  --signature-bundle ../hoolicy-artifacts/decision.sigstore.json \
  --key cosign.pub
```

Keyless verification requires both exact `--identity` and `--issuer`. Missing signatures, wrong identity, wrong issuer, changed statement, or changed evidence fail closed.

Attestation and signature bundle are staged under temporary names. A failed Cosign operation does not publish a final unsigned statement or partial signature bundle.

External evidence is declared in `.hoolicy/evidence.yaml`. Every artifact needs an exact SHA-256 digest and built-subject digest. Supported local adapters follow the [SARIF 2.1.0 schema](https://github.com/oasis-tcs/sarif-spec/blob/main/sarif-2.1/schema/sarif-schema-2.1.0.json), [CycloneDX 1.x JSON model](https://cyclonedx.org/docs/1.6/json/), [SPDX 2.2/2.3 model](https://spdx.github.io/spdx-spec/v2.3/), JUnit XML, and [in-toto Statement v1](https://github.com/in-toto/attestation/blob/main/spec/v1/statement.md). SPDX subjects may be selected by `documentDescribes` or a document `DESCRIBES` relationship. Optional freshness and item/failure thresholds are enforced without running a scanner.

Subject and producer binding is field-specific; a matching string in an unrelated note never counts:

- SARIF uses `runs[].properties["hoolicy.subjectDigest"]`, `tool.driver.name` or `fullName`, and invocation `endTimeUtc` (or `hoolicy.generatedAt`).
- CycloneDX uses `metadata.component.hashes`, `metadata.tools`, and `metadata.timestamp`.
- SPDX uses a SHA-256 checksum on an element named by `documentDescribes`, `creationInfo.creators`, and `creationInfo.created`.
- in-toto provenance uses `subject[].digest.sha256`, the predicate builder ID,
  and a predicate completion timestamp. SLSA Verification Summary Attestations
  additionally require their defined verifier, resource, policy, result,
  levels, SLSA version, and verification timestamp fields; producer binding
  uses `verifier.id`, freshness uses `timeVerified`, and `FAILED` counts as a
  failure.
- JUnit uses explicit `hoolicy.subjectDigest` and `hoolicy.producer` properties plus the suite timestamp. It requires a single `testsuites` XML root with flat child suites, rejects nested or misplaced suites/testcases, and rejects aggregate test/failure/error totals that understate the child suites or present testcase results. Count-only producers remain supported.

Adapters validate required structural fields before applying subject, producer, freshness, and threshold policy. They do not claim full conformance certification for every optional field in the upstream format.

Evidence bundles and referenced external artifacts are limited to 64 MiB each and must be regular, non-symlink files. Larger specialist output must be reduced by its producer without removing the subject, producer, timestamp, or policy-relevant result fields.

Hoolicy proves which configured policy ran, against which local revision and pinned inputs, and what deterministic decision it produced. It does not prove that an omitted scanner ran, that a control mapping equals certification, that a waiver was a good business decision, that an identity was organizationally authorized beyond configured trust policy, or that deployed runtime state matches repository state.

Control status remains interpretation separate from rule results: `passed`, `failed`, `waived`, `not-evaluated`, or `unmapped`. An unmapped or not-evaluated control is never converted into a pass.
