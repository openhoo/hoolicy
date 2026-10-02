# Rules, packs, baselines, and waivers

## Small self-contained rule

```yaml
version: 1
project: my-service
failOn: error
rules:
  - id: repository.security-policy
    title: Repository documents vulnerability reporting
    description: Requires SECURITY.md at repository root.
    rationale: Contributors need a private reporting channel.
    remediation: Add reviewed vulnerability-reporting instructions.
    severity: error
    kind: files
    files: [SECURITY.md]
    spec:
      mode: require
      message: SECURITY.md is required
```

Every rule explains what/why/remediation and uses a supported kind/spec.
Structured rules use bounded CEL or built-in kinds; arbitrary shell commands
are not supported. For elaborate rule kinds, consult the installed release's
versioned schema and upstream rule guide rather than inventing fields.

## Versioned remote packs

Add this block to the existing version 1 policy when the repository naming
pack is actually wanted:

```yaml
packs:
  - name: repository
    git: https://github.com/openhoo/hoolicy.git
    ref: v0.4.0
    subdir: packs/repository
```

Resolve with `hoolicy pack update repository`, review vendored content and
`hoolicy.lock`, then run `hoolicy validate` and `hoolicy check`. Those later
commands operate offline and fail on tampering. Pack parameters must reflect
the repository's existing naming/source conventions. Do not require every
available pack just because it exists.

## Baseline review

`hoolicy baseline create` previews an exact digest-bound baseline;
`hoolicy baseline create --apply` writes the reviewed decision. Default path
is `.hoolicy/baseline.json`. Matching requires rule ID, severity, complete rule
digest, and finding digest. Full checks retain existing findings while new or
materially changed findings can block. Invalid/stale baselines fail closed.

Checks do not edit baselines. `hoolicy baseline prune` previews removed entries;
review before `--apply`. Fixed/stale lifecycle states are evidence for that
review, not authorization to erase debt automatically.

## Waivers and comparison

Waivers need owner, HTTPS ticket, meaningful reason, narrow scope, creation,
and expiry within 90 days. Use `hoolicy waiver --help` for the installed version's
preview/apply operation and keep exact finding binding. Do not invent approval
details or use a waiver for malformed configuration.

`hoolicy report diff before.json after.json` compares stored policy reports by
fingerprints/digests. `check --base REV` compares full Git snapshots and needs
a locally available base commit; a shallow clone may need an explicit fetch.
Machine-report upload must preserve 0/1/2 check status. Hoolicy's GitLab format
is `gitlab-codequality`, distinct from Hooray's `gitlab-code-quality`.
