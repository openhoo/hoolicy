package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

func boundaryReport(t *testing.T) (*engine.Report, *config.Project, []sdk.Rule) {
	t.Helper()
	root := t.TempDir()
	project := &config.Project{Project: "demo", Root: root, Path: filepath.Join(root, config.DefaultFilename), Waivers: config.DefaultWaivers, Evidence: config.DefaultEvidence, FailOn: sdk.SeverityWarning}
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Severity: sdk.SeverityWarning, Remediation: "Fix", Kind: "files"}
	rules := []sdk.Rule{rule}
	digest, err := engine.ProjectDigest(project, rules)
	if err != nil {
		t.Fatal(err)
	}
	finding := sdk.Finding{Message: "violation", Location: sdk.Location{Path: "README.md"}}
	finding.Finalize(rule)
	input := &engine.Report{ReportVersion: 2, Tool: engine.Tool{Name: "hoolicy", Version: "test"}, Project: "demo", GeneratedAt: time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC), ConfigDigest: digest, PolicyDigest: digest, Git: sdk.GitContext{CommitSubjects: []sdk.Commit{}}, FailOn: project.FailOn, Findings: []sdk.Finding{finding}, Waivers: []config.Waiver{}, Metrics: engine.EvaluationMetrics{Rules: []engine.RuleMetric{}}}
	input.Summary = summarizeMigrated(input.Findings, input.FailOn, len(rules))
	return input, project, rules
}

func TestValidateV2RejectsWeakenedThreshold(t *testing.T) {
	input, project, rules := boundaryReport(t)
	input.FailOn = sdk.SeverityError
	input.Summary = summarizeMigrated(input.Findings, input.FailOn, len(rules))
	if err := ValidateV2(input, project, rules); err == nil || !strings.Contains(err.Error(), "failOn") {
		t.Fatalf("a report weakened the configured decision threshold: %v", err)
	}
}

func TestValidateV2AllowsStrongerThreshold(t *testing.T) {
	input, project, rules := boundaryReport(t)
	input.FailOn = sdk.SeverityInfo
	input.Summary = summarizeMigrated(input.Findings, input.FailOn, len(rules))
	if err := ValidateV2(input, project, rules); err != nil {
		t.Fatalf("valid stronger check threshold rejected: %v", err)
	}
}

func TestMigrateJSONRejectsWeakenedHistoricalThreshold(t *testing.T) {
	input, project, rules := boundaryReport(t)
	finding := input.Findings[0]
	finding.Fingerprint = legacyFindingFingerprint(finding)
	digest, err := LegacyProjectDigest(project, rules)
	if err != nil {
		t.Fatal(err)
	}
	legacy := legacyReport{
		ReportVersion: 1, Tool: input.Tool, Project: project.Project, GeneratedAt: input.GeneratedAt,
		ConfigDigest: digest, Git: input.Git, FailOn: sdk.SeverityError,
		Findings: []legacyFinding{{RuleID: finding.RuleID, Title: finding.Title, Message: finding.Message, Remediation: finding.Remediation, Severity: finding.Severity, Location: finding.Location, Key: finding.Key, Fingerprint: finding.Fingerprint}},
		Summary:  legacySummary{Rules: 1, Warnings: 1},
	}
	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(project.Root, "legacy-report.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateJSON(path, project, rules, digest); err == nil || !strings.Contains(err.Error(), "failOn") {
		t.Fatalf("historical report weakened its configured threshold: %v", err)
	}
	legacy.FailOn = sdk.SeverityInfo
	legacy.Summary.Blocking = 1
	data, err = json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if migrated, err := MigrateJSON(path, project, rules, digest); err != nil || migrated.FailOn != sdk.SeverityInfo || migrated.Summary.Blocking != 1 {
		t.Fatalf("historical report with a valid stronger threshold rejected: report=%v err=%v", migrated, err)
	}
}

func TestValidateV2BindsWaiverToFindingScope(t *testing.T) {
	for _, scope := range []string{"fingerprint mismatch", "path mismatch", "fingerprint match", "path match"} {
		t.Run(scope, func(t *testing.T) {
			input, project, rules := boundaryReport(t)
			waiver := config.Waiver{ID: "demo.review", Rule: rules[0].ID, Reason: "A reviewed exception scoped to an exact finding.", Owner: "team@example.invalid", Ticket: "https://issues.example.invalid/DEMO-1", Created: config.Date{Time: input.GeneratedAt.Truncate(24 * time.Hour)}, Expires: config.Date{Time: input.GeneratedAt.Truncate(24*time.Hour).AddDate(0, 0, 10)}}
			switch scope {
			case "fingerprint mismatch":
				waiver.Fingerprints = []string{strings.Repeat("a", 64)}
			case "path mismatch":
				waiver.Paths = []string{"other.txt"}
			case "fingerprint match":
				waiver.Fingerprints = []string{input.Findings[0].Fingerprint}
			case "path match":
				waiver.Paths = []string{"README.md"}
			}
			input.Waivers = []config.Waiver{waiver}
			input.Findings[0].Waived, input.Findings[0].WaiverID = true, waiver.ID
			input.Findings[0].State, input.Findings[0].StateSource = sdk.FindingWaived, "waiver"
			input.Summary = summarizeMigrated(input.Findings, input.FailOn, len(rules))
			err := ValidateV2(input, project, rules)
			if strings.Contains(scope, "mismatch") {
				if err == nil || !strings.Contains(err.Error(), "waiver scope") {
					t.Fatalf("out-of-scope waiver accepted: %v", err)
				}
			} else if err != nil {
				t.Fatalf("valid waiver scope rejected: %v", err)
			}
		})
	}
}

func TestValidateV2RejectsSuppressedLifecycleFindings(t *testing.T) {
	for _, state := range []sdk.FindingState{sdk.FindingWaived, sdk.FindingExisting} {
		t.Run(string(state), func(t *testing.T) {
			input, project, rules := boundaryReport(t)
			finding := sdk.Finding{Message: "Invalid baseline metadata"}
			finding.Finalize(sdk.Rule{ID: "hoolicy.baseline", Title: "Hoolicy policy lifecycle", Remediation: "Correct or remove the invalid policy metadata.", Severity: sdk.SeverityError})
			finding.State = state
			if state == sdk.FindingExisting {
				finding.StateSource = "baseline"
			} else {
				waiver := config.Waiver{ID: "demo.review", Rule: finding.RuleID, Fingerprints: []string{finding.Fingerprint}, Reason: "A forged waiver must not suppress lifecycle errors.", Owner: "team@example.invalid", Ticket: "https://issues.example.invalid/DEMO-1", Created: config.Date{Time: input.GeneratedAt.Truncate(24 * time.Hour)}, Expires: config.Date{Time: input.GeneratedAt.Truncate(24*time.Hour).AddDate(0, 0, 10)}}
				input.Waivers = []config.Waiver{waiver}
				finding.Waived, finding.WaiverID, finding.StateSource = true, waiver.ID, "waiver"
			}
			input.Findings = []sdk.Finding{finding}
			input.Summary = summarizeMigrated(input.Findings, input.FailOn, len(rules))
			if err := ValidateV2(input, project, rules); err == nil || !strings.Contains(err.Error(), "cannot be suppressed") {
				t.Fatalf("lifecycle failure was suppressed: %v", err)
			}
		})
	}
}

func TestValidateV2CountsLifecycleChanges(t *testing.T) {
	for _, state := range []string{"fixed", "stale"} {
		t.Run(state, func(t *testing.T) {
			input, project, rules := boundaryReport(t)
			finding := input.Findings[0]
			input.Changes = []engine.Change{{State: state, Source: "baseline", Fingerprint: finding.Fingerprint, RuleID: finding.RuleID, Severity: finding.Severity, PolicyDigest: finding.PolicyDigest, FindingDigest: finding.FindingDigest}}
			if state == "fixed" {
				input.Summary.Fixed = 1
			} else {
				input.Summary.Stale = 1
			}
			if err := ValidateV2(input, project, rules); err != nil {
				t.Fatalf("valid lifecycle change summary rejected: %v", err)
			}
			input.Summary.Fixed, input.Summary.Stale = 0, 0
			if err := ValidateV2(input, project, rules); err == nil {
				t.Fatal("understated lifecycle change summary accepted")
			}
			input.Changes[0].State = "forged"
			if err := ValidateV2(input, project, rules); err == nil || !strings.Contains(err.Error(), "invalid change state") {
				t.Fatalf("invalid lifecycle state accepted: %v", err)
			}
		})
	}
}
