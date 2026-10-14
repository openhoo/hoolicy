# Policy explanations

Use this extension only with a binary that supports `explanation`; older strict
binaries reject it. Keep required `description`, `rationale`, and `remediation`.
Add guidance specific to the rule's intended outcome:

```yaml
explanation:
  expectation: Production debug mode is explicitly false.
  impact: Debug output can expose internal service details.
  steps:
    - Review the reported configuration with the service owner.
    - Set debug to false and rerun the same check.
  references:
    - title: Configuration runbook
      url: https://docs.example.com/runbooks/configuration#debug
```

Fields are optional, but an explanation must contain guidance. Expectation,
impact, and steps are limited to 4,096 UTF-8 bytes each, with at most 16 steps.
There may be eight references, with titles of at most 256 bytes and URLs of
at most 2,048 bytes. References require absolute HTTPS URLs without credentials
or query parameters. Steps are prose and never executed; references are never
fetched during checks. Unknown fields and duplicate YAML keys are rejected.

Text output groups explanations by rule and names each occurrence's disposition:
blocking, below the `failOn` threshold, existing through baseline/base comparison,
or accepted by a named waiver. JSON findings include `policy` context; SARIF,
JUnit, GitHub summaries, GitLab Code Quality, and inventory carry guidance too.
GitLab Code Quality can omit findings without locations; its empty array alone
does not prove policy success.

```sh
hoolicy list --format json
hoolicy explain --format json service.production-debug
hoolicy check --format json > report.json 2> diagnostic.json
hoolicy check --format sarif --output hoolicy.sarif --error-format json
```

Preserve exit 0/1/2. Exit 2 means invalid configuration, parsing, unsafe state,
evaluation, or report writing failed. JSON operational diagnostics are on
stderr with `diagnosticVersion: 1`, an error code, phase, message, exit code,
and rule guidance when known. The `arguments` phase identifies parsed option
or positional-argument errors; `output` identifies report destination/write
failures. Text diagnostics separate the next operational action from policy
guidance. They are not a completed decision report.
Correct the cause and rerun; do not baseline or waive an operational error.
Help and flag-parser usage remain human-readable. `--error-format text`
selects readable errors even with a JSON report.

Adding guidance changes the policy digest and requires baseline review.
Policies without the new field retain historical decision digests.
Use latest project/pack editor schemas when authoring explanations; historical
`schemas/v1/hoolicy.schema.json` and `pack.schema.json` remain immutable and do
not admit this field. Give distributed packs an appropriate binary compatibility
floor once the feature is released.
