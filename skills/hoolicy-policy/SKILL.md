---
name: hoolicy-policy
description: Adopt Hoolicy in a consumer repository, author and validate strict policies, run offline checks, vendor policy packs, review safe fixes, and manage explicit baselines or waivers with preserved CI decisions.
---

# Adopt and use Hoolicy policy

Work in the consuming repository. Inspect its existing `hoolicy.yaml`, lock,
waivers/baseline, Git state, and CI before adding policy. Skill installation
supplies instructions, not the binary or remote packs. Read
[adoption.md](references/adoption.md) for rules, packs, debt, and report contracts.

## Install and begin

Reuse the project's approved binary. A concrete published example is:

```bash
go install github.com/openhoo/hoolicy/cmd/hoolicy@v0.4.0
```

Use an approved version/digest when already selected; this example is not a
latest-version claim. Container checks can mount the repository read-only and
use the caller's UID/GID to preserve access to private files; rootless Podman
also needs `--userns=keep-id`. Do not loosen host file permissions for the image.

For a new repository policy:

```bash
hoolicy init --project my-service
hoolicy validate
hoolicy check
```

Standard creates repository/documentation/Git/source rules; strict adds image
digest requirements; empty creates the strict configuration skeleton only.
Reuse an existing policy rather than overwriting it. Begin with checks that
express the project's actual decisions, not every available rule.

## Evaluate and remediate

1. Validate before checking. Unknown keys, duplicate IDs/keys, bad specs/paths,
   and invalid CEL are configuration errors, not findings to suppress.
2. Use `hoolicy list` and `hoolicy explain` to understand active rule provenance,
   rationale, and remediation; use command help for its exact rule selection.
3. Run `hoolicy check` and preserve exit status: 0 passed; 1 a new finding met
   `failOn`; 2 configuration/evaluation/output failed.
4. Repair the demonstrated rule violation and rerun the same policy. New custom
   pack rules need a passing and failing fixture, proved with `hoolicy test`.
5. Use `hoolicy fix` to preview available safe fixes and review its diff. Apply
   only the intended edits with `--apply`; do not force dirty or symlink targets.

`hoolicy check` runs offline and never executes scripts from packs. Explicit
`pack update` vendors code/data and updates the lock; review that change before
depending on it. Do not bypass digest/tampering failures by deleting the lock.

## Adoption and CI

Existing debt can be recorded with a reviewed exact baseline while full checks
still evaluate the repository. Do not baseline new defects merely to get green.
Temporary waivers need owned, narrow, justified, ticketed expiry decisions.

```bash
hoolicy check --format sarif --output hoolicy.sarif
hoolicy check --format gitlab-codequality --output gl-code-quality-report.json
```

Keep normal failure status when uploading reports. A valid empty report can omit
unlocatable findings and therefore does not supersede the policy decision.
For base comparisons, fetch the intended revision first and use
`hoolicy doctor --base origin/main`, then `hoolicy check --base origin/main`.
Report policy, revision, rule/finding evidence, and any applied baseline/waiver.
