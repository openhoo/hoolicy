# Error output and policy explanation review

Scope: policy authoring metadata, SDK finding finalization, engine diagnostics,
human output, native CI reports, inventory, discovery commands, starter profiles,
schema compatibility, and actual CLI acceptance. Base: `d27314d`, version 0.6.1.
Implementation branch: `feat/policy-explanations`.

## Findings and repairs

| Problem | Repair | Regression evidence |
| --- | --- | --- |
| Report readers lost configured description and rationale. | Bind policy context during finding finalization and carry it through all six report formats. | `TestEveryReportCarriesPolicyGuidance`, CLI discovery/report tests |
| A generic remediation could not describe expectations, impact, or ordered actions. | Add strictly validated optional explanation metadata with bounded steps and HTTPS references. | SDK validation and config expansion tests |
| A rule could supply misleading policy context in a finding. | Finalization replaces supplied guidance with an independent copy from the configured rule; supplied report context must match. | `TestExplanationIsAuthoritativeIndependentAndDigestBound`, `TestPolicyExplanationCannotBeForgedInReport` |
| Repeated findings buried contributors in repeated instructions and fingerprint ordering. | Group text by rule, print guidance once, prioritize blocking groups, and sort occurrences by source position. | Text grouping and priority tests |
| Severity alone did not explain whether a finding blocks the check. | Show blocking, threshold, baseline/base, and named waiver dispositions. | `TestTextGroupsGuidanceAndExplainsEveryDisposition` |
| Evaluation failures lacked rule, phase, and authored context. | Preserve typed operational causes and emit separate text/JSON diagnostics on stderr. | CLI validation/parser/configuration matrix; diagnostic checked-write tests |
| Total execution timeout erased the active rule context. | Preserve contextual rule errors through cancellation and the outer timeout finalizer. | `TestTotalBudgetFailureRetainsActiveRuleContext` |
| Standalone JSON reports emitted `commits: null`, violating the published report schema. | Normalize absent commit lists to an empty array in completed decisions. | `TestStandaloneDecisionSatisfiesReportContract`; native schema validation |
| Explanation text could forge terminal lines or markup. | Sanitize control and directional formatting characters in human output; escape GitHub summary markup. | Human-output injection and JSON preservation tests |
| Pack comparisons did not expose the new metadata. | Include explanation changes in metadata diffs. | `TestPackCompareIncludesExplanationChanges` |
| Unexpected positional arguments ignored a requested JSON diagnostic format. | Select the diagnostic format before validating parsed arguments and identify argument failures explicitly. | `TestCheckParsedArgumentDiagnosticsRespectFormat`; native argument failures |
| Report destination and stream failures were labeled as generic execution errors. | Identify the output phase, retain checked writes, and give destination-specific guidance. | Output destination/short-write regressions; native destination controls |
| Operational parser errors interleaved policy repair steps with the next operational action. | Give one phase-specific next action and place authored guidance in a separate informational section. | `TestOperationalGuidanceIsSeparateFromPolicyRemediation` |
| GitHub summaries omitted workspace and column; partial routing metadata produced empty text labels. | Preserve complete available locations and emit only populated routing labels. | `TestHumanReportsKeepWorkspaceAndCompleteLocations`; native workspace cases |
| Finding-budget exhaustion dropped the active rule and explanation. | Return a contextual finding-phase error without a partial decision report. | `TestFindingBudgetFailureRetainsActiveRuleContext`; native budget failure |

## Contracts

- Config version 1, JSON report version 2, inventory version 1, and exit 0/1/2
  remain in use. Diagnostic envelopes have a new independent version 1.
- Existing rule/finding fingerprint and digest golden checks remain enforced.
  The enriched report has a new golden hash; removing its optional policy
  context reproduces the complete historical report hash.
- Explanation edits change the rule policy digest and therefore require review
  of previously accepted baseline findings.
- Existing files in `schemas/v1/` are untouched. Latest schemas allow only
  explicitly reviewed optional extensions; new standalone schemas have v1 pairs.
- Reference URLs are never fetched and steps are never executed by checks.
- Failed checks leave an existing output report untouched. Diagnostics cannot
  masquerade as a completed decision or be accepted through finding baselines.

## Acceptance

Verified on the local macOS host:

- `go test ./...`
- `go test -race ./...`
- `go vet ./...`
- Formatting and `git diff --check`
- Native binary: 109 CLI cases including all six formats, real baseline
  preview/application, guidance changes invalidating exact baseline acceptance,
  fixed findings, waiver preview/application/expiry/staleness, stricter warning
  thresholds, multiple occurrences, real Git base comparisons, workspace owner
  routing and pack context, argument/destination/budget errors, report
  preservation, atomic final-symlink replacement, discovery, and starters
- All 36 latest/versioned schema files checked; emitted JSON report, inventory,
  diagnostics, and starter explanations validated with their schemas
- Native pack fixture tests: 305/305 passed
- Native repository dogfood: four rules, zero findings, exit 0

All listed checks passed. The local verification receipt records the final
source fingerprint alongside the native acceptance evidence. No release was requested.
Cross-platform CI execution is outside this local qualification.

Local receipts and actual output:
`/Users/wakemeup/projects/openhoo/output/hoolicy-explanations-20261014/`.
The `smoke.py` and `expanded-smoke.py` harnesses use isolated temporary policies,
temporary Git repositories, and a local schema registry. They neither fetch
schema references nor edit the repository example. `expanded-native-verification.json`
records native cases; `verification.json` binds the final source and binary.
