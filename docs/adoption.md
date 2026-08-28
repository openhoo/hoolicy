# Adopt Hoolicy with a baseline

Hoolicy always evaluates the complete repository. A baseline changes the decision state, not the evaluation scope: exact reviewed findings become `existing`; new or materially changed findings remain `new` and can block delivery.

## Create a reviewed baseline

Run a normal check first. Correct configuration errors and waive only findings that have a time-bounded, owned exception. Then preview the baseline:

```sh
hoolicy baseline create
```

The preview contains the project, revision, tool version, creation time, policy digest, and each finding's fingerprint, severity, policy digest, and finding digest. Review it in the same change as the policy. Write the exact preview only after review:

```sh
hoolicy baseline create --apply
```

The default path is `.hoolicy/baseline.json`. Configure `baseline:` only when the repository needs another relative path.

Baseline matching fails closed. A fingerprint is existing only when rule ID, severity, complete rule digest, and finding content digest still match. Invalid files, different fingerprints, changed severity, or changed policy content never suppress a current finding.

## Review lifecycle changes

`hoolicy check` distinguishes `new`, `existing`, and `waived` findings. It also reports:

- `fixed`: the same policy no longer reproduces a baseline fingerprint.
- `stale`: the rule disappeared, its policy digest changed, or finding content changed materially.

Checks never edit the baseline. Preview explicit cleanup, review removed entries, then apply it:

```sh
hoolicy baseline prune
hoolicy baseline prune --apply
```

## Compare Git decisions and reports

Pass a locally available base revision. Hoolicy evaluates both complete repository snapshots with current policy and compares decisions by fingerprint and digests:

```sh
hoolicy check --base origin/main
```

Shallow clones must fetch the base revision. `hoolicy doctor --base origin/main` reports a precise failure before policy evaluation when it is unavailable.

Compare stored JSON reports deterministically:

```sh
hoolicy report diff before.json after.json
hoolicy report diff --format json before.json after.json
```

CI examples cover [GitHub Actions](../examples/ci/github-actions.yml) and [GitLab CI](../examples/ci/gitlab-ci.yml). GitLab output follows its Code Quality subset: one JSON array with repository-relative locations and supported severities.
