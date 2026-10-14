# Explain policy failures

A contributor should be able to act on a finding without locating its policy
source first. Hoolicy includes configured descriptions and rationale in reports
and supports optional `explanation` metadata on project and pack rules.

## Author guidance next to the rule

Keep the existing required fields: `description` says what is checked,
`rationale` says why the policy exists, and `remediation` describes the safe
outcome. Add `explanation` when a contributor needs a specific expectation,
impact, ordered actions, or a reference:

```yaml
explanation:
  expectation: Production debug mode is explicitly false.
  impact: Debug output can disclose internal service details.
  steps:
    - Review the reported configuration with the service owner.
    - Set debug to false in the production configuration.
    - Rerun the same Hoolicy check.
  references:
    - title: Configuration runbook
      url: https://docs.example.com/runbooks/configuration#debug
```

All four fields are optional; an explanation must contain some guidance.
Expectation, impact, and each step are limited to 4,096 UTF-8 bytes. There may
be at most 16 steps and eight references. Reference titles are limited to 256
bytes and URLs to 2,048 bytes. URLs must be absolute HTTPS references without
credentials or query parameters. Fragments are supported. Checks do not fetch
references or execute steps.

Use prose that remains true for every occurrence of the rule. The finding's
`message` describes the observed violation and its `location` identifies the
input. Avoid putting secrets or raw configuration values into guidance.
Pack parameters can supply whole text values and lists using normal typed
`{{ parameter }}` expansion. Reference URLs must be literal HTTPS URLs;
expanded guidance is validated again before evaluation.

## Read a decision

The text report starts with the blocking count and `failOn`, groups findings
by rule, and prints each rule's guidance once. Every occurrence includes its
actual message, location, disposition, workspace, and owner where available:

- **Blocking:** a new finding reaches `failOn` and makes the check return 1.
- **Non-blocking:** a new finding is below `failOn`; it remains visible.
- **Existing:** the exact finding was accepted by a baseline or base revision.
- **Waived:** a reviewed waiver accepts this finding and its ID is displayed.

No location is invented. A finding without a file is labeled `repository`;
an unknown column is omitted. Older rules automatically contribute their
existing description, rationale, and remediation fields.

```sh
hoolicy list
hoolicy list --format json
hoolicy explain --format json service.production-debug
hoolicy inventory
```

JSON findings carry an optional `policy` object with the configured
`description`, `rationale`, `kind`, `packVersion`, and `explanation`. Inventory
includes the same context, title, and remediation. SARIF rule help, JUnit test
details, GitHub summaries, and GitLab Code Quality descriptions also include
guidance. GitLab Code Quality still omits findings without a usable file
location; preserve Hoolicy's exit status to retain the complete decision.

## Distinguish an incomplete check

Malformed configuration or documents, invalid rule specs, unsafe inputs, and
execution failures return **2**. They do not establish a completed policy
decision. Rule diagnostics identify the rule, source, workspace where known,
and the failure phase: `validation`, `input`, `evaluation`, or `finding`.
The underlying parser or evaluation error remains visible.

Configuration discovery/loading uses `configuration`; pack resolution uses
`pack-resolution`; parsed command options use `arguments`; report destination
and write failures use `output`. Unclassified operational failures use
`execution`. A finding-budget failure retains the active rule and its guidance.
Every text diagnostic provides a phase-specific next action. Policy steps and
remediation appear in a separate informational section labeled as having no
completed decision. A parser error cannot be resolved by accepting a finding.

With JSON reports, operational diagnostics are JSON on **stderr**, while
completed decisions remain on stdout or in the selected report file:

```sh
hoolicy check --format json > report.json 2> diagnostic.json
hoolicy check --format sarif --output hoolicy.sarif --error-format json
hoolicy check --format json --error-format text
```

The diagnostic envelope has `diagnosticVersion: 1` and an `error` containing
`code`, `phase`, `message`, and `exitCode: 2`. Rule diagnostics additionally
carry `ruleId`, `title`, `workspace`, `pack`, `remediation`, and `policy` as
available. Help and flag-parser usage output remain human-readable.
Once flags parse successfully, option and positional-argument errors honor
the selected diagnostic format too.
A failed evaluation leaves an existing `--output` report untouched.

## Compatibility and trust

This is an additive config-version-1 and report-version-2 extension. Policies
without `explanation` retain their existing rule and project digests. Finding
fingerprints and finding digests retain their historical calculation. Adding
or changing explanation metadata changes the **policy** digest, so previously
accepted baselines require review under the changed policy.

The engine binds guidance from the configured rule. A custom rule implementation
cannot replace it. Report validation accepts historical v2 reports without
`policy`; supplied context must match the configured rule exactly. Human output
removes terminal controls and directional formatting controls, and GitHub
summaries escape authored markup. Machine JSON preserves the authored text.

Previously published files in `schemas/v1/` remain unchanged. Use the latest
`schemas/hoolicy.schema.json` or `schemas/pack.schema.json` for editors when
authoring this extension; older versioned project/pack schemas do not admit it.
The new explanation, context, and diagnostic schemas have their own v1 copies.
Older Hoolicy binaries reject the new config field through strict validation.
When publishing a pack, declare a Hoolicy compatibility floor that contains
this feature.

See [the runnable example](../examples/policy-explanations/) for a deliberately
failing configuration and its expected repair.
