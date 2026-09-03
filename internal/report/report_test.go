package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

func TestLoadJSONRejectsOversizedInput(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "report.json")
	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(path, MaxReportFileSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadJSON(path); err == nil || !strings.Contains(err.Error(), "larger") {
		t.Fatalf("oversized report accepted: %v", err)
	}
}

func TestMigrateJSONPreservesV1FingerprintForWaiverScope(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	waiverPath := filepath.Join(root, config.DefaultWaivers)
	if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("version: 1\nproject: demo\nfailOn: error\nwaivers: .hoolicy/waivers.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	rule := sdk.Rule{ID: "demo.required", Title: "Required file", Description: "A required file.", Rationale: "The repository needs this file.", Remediation: "Add README.md.", Severity: sdk.SeverityError, Kind: "files"}
	project := &config.Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Root: root, Path: configPath, Waivers: ".hoolicy/waivers.yaml"}
	waivedFinding := sdk.Finding{RuleID: rule.ID, Title: rule.Title, Message: "README.md is missing", Remediation: rule.Remediation, Severity: rule.Severity, Location: sdk.Location{Path: "README.md", Line: 1, Column: 1}, Key: "required"}
	waivedFinding.Fingerprint = legacyFindingFingerprint(waivedFinding)
	unwaivedFinding := sdk.Finding{RuleID: rule.ID, Title: rule.Title, Message: "LICENSE is missing", Remediation: rule.Remediation, Severity: rule.Severity, Location: sdk.Location{Path: "LICENSE", Line: 1, Column: 1}, Key: "required"}
	unwaivedFinding.Fingerprint = legacyFindingFingerprint(unwaivedFinding)
	waiverData := "version: 1\nwaivers:\n  - id: demo.review\n    rule: demo.required\n    fingerprints:\n      - " + waivedFinding.Fingerprint + "\n    reason: Temporary exception while reviewed remediation is delivered.\n    owner: team@example.com\n    ticket: https://issues.example.com/DEMO-1\n    created: 2026-08-01\n    expires: 2026-09-01\n"
	if err := os.WriteFile(waiverPath, []byte(waiverData), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.DefaultEvidence), []byte("evidence policy input\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	input := legacyReport{
		ReportVersion: 1, Tool: engine.Tool{Name: "hoolicy", Version: "0.1.2"}, Project: "demo",
		GeneratedAt: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), ConfigDigest: "",
		Git: sdk.GitContext{CommitSubjects: []sdk.Commit{}}, FailOn: sdk.SeverityError,
		Findings: []legacyFinding{
			{RuleID: waivedFinding.RuleID, Title: waivedFinding.Title, Message: waivedFinding.Message, Remediation: waivedFinding.Remediation, Severity: waivedFinding.Severity, Location: waivedFinding.Location, Key: waivedFinding.Key, Fingerprint: waivedFinding.Fingerprint, Waived: true, WaiverID: "demo.review"},
			{RuleID: unwaivedFinding.RuleID, Title: unwaivedFinding.Title, Message: unwaivedFinding.Message, Remediation: unwaivedFinding.Remediation, Severity: unwaivedFinding.Severity, Location: unwaivedFinding.Location, Key: unwaivedFinding.Key, Fingerprint: unwaivedFinding.Fingerprint},
		},
		Summary: legacySummary{Rules: 1, Errors: 2, Waived: 1, Blocking: 1},
	}
	digest, err := LegacyProjectDigest(project, []sdk.Rule{rule})
	if err != nil {
		t.Fatal(err)
	}
	input.ConfigDigest = digest
	reportPath := filepath.Join(root, "report.json")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateJSON(reportPath, project, []sdk.Rule{rule}, digest)
	if err != nil {
		t.Fatal(err)
	}
	if migrated.PolicyDigest == migrated.ConfigDigest {
		t.Fatal("migration reused the historical config digest as the v2 policy digest")
	}
	if len(migrated.Findings) != 2 {
		t.Fatalf("unexpected migrated findings: %#v", migrated.Findings)
	}
	foundWaived := false
	for _, finding := range migrated.Findings {
		if finding.Waived && finding.State == sdk.FindingWaived && finding.WaiverID == "demo.review" {
			foundWaived = true
			if finding.Fingerprint == waivedFinding.Fingerprint {
				t.Fatal("migration did not derive the v2 finding identity")
			}
		}
	}
	if !foundWaived {
		t.Fatalf("historical waiver was not restored: %#v", migrated.Findings)
	}
	if migrated.Summary != (engine.Summary{Rules: 1, Errors: 2, New: 1, Waived: 1, Blocking: 1}) {
		t.Fatalf("unexpected migrated summary: %#v", migrated.Summary)
	}
}

func TestMigrateJSONPreservesExpiredWaiverFinding(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	waiverPath := filepath.Join(root, config.DefaultWaivers)
	if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("version: 1\nproject: demo\nfailOn: error\nwaivers: .hoolicy/waivers.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(waiverPath, []byte("version: 1\nwaivers:\n  - id: demo.expired\n    rule: demo.required\n    fingerprints:\n      - "+strings.Repeat("a", 64)+"\n    reason: Temporary exception while reviewed remediation is delivered.\n    owner: team@example.com\n    ticket: https://issues.example.com/DEMO-2\n    created: 2026-08-01\n    expires: 2026-09-01\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Root: root, Path: configPath, Waivers: ".hoolicy/waivers.yaml"}
	generatedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	expected := historicalWaiverFinding(project, "Invalid waiver demo.expired: waiver is expired", "demo.expired")
	input := legacyReport{
		ReportVersion: 1, Tool: engine.Tool{Name: "hoolicy", Version: "0.1.2"}, Project: "demo",
		GeneratedAt: generatedAt, Git: sdk.GitContext{CommitSubjects: []sdk.Commit{}}, FailOn: sdk.SeverityError,
		Findings: []legacyFinding{{RuleID: expected.RuleID, Title: expected.Title, Message: expected.Message, Remediation: expected.Remediation, Severity: expected.Severity, Location: expected.Location, Key: expected.Key, Fingerprint: expected.Fingerprint}},
		Summary:  legacySummary{Rules: 0, Errors: 1, Blocking: 1},
	}
	digest, err := LegacyProjectDigest(project, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.ConfigDigest = digest
	reportPath := filepath.Join(root, "report.json")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateJSON(reportPath, project, nil, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrated.Findings) != 1 || len(migrated.Waivers) != 0 || !strings.Contains(migrated.Findings[0].Message, "waiver is expired") {
		t.Fatalf("expired waiver migration lost lifecycle finding: %#v", migrated)
	}
}

func TestMigrateJSONPreservesDuplicateWaiverFindings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	waiverPath := filepath.Join(root, config.DefaultWaivers)
	if err := os.MkdirAll(filepath.Dir(waiverPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte("version: 1\nproject: demo\nfailOn: error\nwaivers: .hoolicy/waivers.yaml\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waiver := "    rule: demo.required\n    fingerprints:\n      - " + strings.Repeat("a", 64) + "\n    reason: Temporary exception while reviewed remediation is delivered.\n    owner: team@example.com\n    ticket: https://issues.example.com/DEMO-3\n    created: 2026-08-01\n    expires: 2026-09-01\n"
	if err := os.WriteFile(waiverPath, []byte("version: 1\nwaivers:\n  - id: demo.duplicate\n"+waiver+"  - id: demo.duplicate\n"+waiver), 0o644); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Root: root, Path: configPath, Waivers: ".hoolicy/waivers.yaml"}
	generatedAt := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	invalid := historicalWaiverFinding(project, "Invalid waiver demo.duplicate: waiver is expired", "demo.duplicate")
	duplicate := historicalWaiverFinding(project, "Duplicate waiver ID: demo.duplicate", "demo.duplicate")
	input := legacyReport{
		ReportVersion: 1, Tool: engine.Tool{Name: "hoolicy", Version: "0.1.2"}, Project: "demo",
		GeneratedAt: generatedAt, Git: sdk.GitContext{CommitSubjects: []sdk.Commit{}}, FailOn: sdk.SeverityError,
		Findings: []legacyFinding{
			{RuleID: invalid.RuleID, Title: invalid.Title, Message: invalid.Message, Remediation: invalid.Remediation, Severity: invalid.Severity, Location: invalid.Location, Key: invalid.Key, Fingerprint: invalid.Fingerprint},
			{RuleID: duplicate.RuleID, Title: duplicate.Title, Message: duplicate.Message, Remediation: duplicate.Remediation, Severity: duplicate.Severity, Location: duplicate.Location, Key: duplicate.Key, Fingerprint: duplicate.Fingerprint},
		},
		Summary: legacySummary{Rules: 0, Errors: 2, Blocking: 2},
	}
	digest, err := LegacyProjectDigest(project, nil)
	if err != nil {
		t.Fatal(err)
	}
	input.ConfigDigest = digest
	reportPath := filepath.Join(root, "report.json")
	data, err := json.Marshal(input)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(reportPath, data, 0o644); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateJSON(reportPath, project, nil, digest)
	if err != nil {
		t.Fatal(err)
	}
	if len(migrated.Findings) != 2 || len(migrated.Waivers) != 0 {
		t.Fatalf("duplicate waiver migration lost lifecycle findings: %#v", migrated)
	}
	messages := migrated.Findings[0].Message + "\n" + migrated.Findings[1].Message
	if !strings.Contains(messages, "waiver is expired") || !strings.Contains(messages, "Duplicate waiver ID") {
		t.Fatalf("duplicate waiver lifecycle findings missing: %#v", migrated.Findings)
	}
}

func TestLegacyProjectDigestExcludesEvidence(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	if err := os.WriteFile(configPath, []byte("version: 1\nproject: demo\nfailOn: error\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Root: root, Path: configPath, Waivers: config.DefaultWaivers, Evidence: config.DefaultEvidence}
	rules := []sdk.Rule{{ID: "demo.required", Title: "Required", Description: "A required file.", Rationale: "The repository needs this file.", Remediation: "Add README.md.", Severity: sdk.SeverityError, Kind: "files"}}
	legacy, err := LegacyProjectDigest(project, rules)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(filepath.Join(root, config.DefaultEvidence)), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, config.DefaultEvidence), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	current, err := engine.ProjectDigest(project, rules)
	if err != nil {
		t.Fatal(err)
	}
	if legacy == current {
		t.Fatalf("v1 digest changed when evidence was added: %s", legacy)
	}
}

func TestMigrateJSONRejectsIncompleteV1Envelope(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	if err := os.WriteFile(configPath, []byte("version: 1\nproject: demo\nfailOn: error\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "demo", FailOn: sdk.SeverityError, Root: root, Path: configPath, Waivers: config.DefaultWaivers}
	reportPath := filepath.Join(root, "report.json")
	if err := os.WriteFile(reportPath, []byte(`{"reportVersion":1,"failOn":"error","configDigest":"sha256:`+strings.Repeat("a", 64)+`","findings":[]}`), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateJSON(reportPath, project, nil, "sha256:"+strings.Repeat("a", 64)); err == nil || !strings.Contains(err.Error(), "missing required v1 field") {
		t.Fatalf("incomplete v1 envelope accepted: %v", err)
	}
}

func TestValidateV2RejectsMissingGitCollections(t *testing.T) {
	t.Parallel()
	project := &config.Project{Project: "demo"}
	input := &engine.Report{
		ReportVersion: 2, Tool: engine.Tool{Name: "hoolicy", Version: "test"}, Project: "demo",
		GeneratedAt:  time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC),
		ConfigDigest: "sha256:" + strings.Repeat("a", 64), PolicyDigest: "sha256:" + strings.Repeat("b", 64),
		FailOn: sdk.SeverityError, Findings: []sdk.Finding{}, Waivers: []config.Waiver{},
		Metrics: engine.EvaluationMetrics{Rules: []engine.RuleMetric{}},
	}
	if err := ValidateV2(input, project, nil); err == nil {
		t.Fatal("v2 report with nil git commits accepted")
	}
}

func TestReportFormats(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo rule", Remediation: "Fix it.", Severity: sdk.SeverityError}
	finding := sdk.Finding{Message: "Failed", Location: sdk.Location{Path: "demo.yaml", Line: 2, Column: 3}}
	finding.Finalize(rule)
	input := &engine.Report{ReportVersion: 1, Tool: engine.Tool{Name: "hoolicy", Version: "test"}, Project: "demo", Findings: []sdk.Finding{finding}, Summary: engine.Summary{Rules: 1, Errors: 1, Blocking: 1}}
	for _, format := range []string{"text", "json", "sarif", "junit", "github", "gitlab-codequality"} {
		t.Run(format, func(t *testing.T) {
			var output bytes.Buffer
			if err := Write(&output, format, input, false); err != nil {
				t.Fatal(err)
			}
			switch format {
			case "text":
				if !strings.Contains(output.String(), "demo.rule Failed") || !strings.Contains(output.String(), "1 blocking") {
					t.Fatalf("unexpected text report: %s", output.String())
				}
			case "json", "sarif", "gitlab-codequality":
				var value any
				if err := json.Unmarshal(output.Bytes(), &value); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
				if format == "gitlab-codequality" {
					items, ok := value.([]any)
					if !ok || len(items) != 1 {
						t.Fatalf("unexpected GitLab report: %#v", value)
					}
					item := items[0].(map[string]any)
					if item["check_name"] != "demo.rule" || item["severity"] != "major" || !strings.Contains(item["description"].(string), "State: new.") || !strings.Contains(item["description"].(string), "Remediation: Fix it.") {
						t.Fatalf("unexpected GitLab finding: %#v", item)
					}
				}
			case "junit":
				var value struct {
					XMLName xml.Name `xml:"testsuites"`
				}
				if err := xml.Unmarshal(output.Bytes(), &value); err != nil {
					t.Fatalf("invalid XML: %v", err)
				}
			case "github":
				if !strings.Contains(output.String(), "Hoolicy policy summary") || !strings.Contains(output.String(), "demo.rule") {
					t.Fatalf("unexpected GitHub summary: %s", output.String())
				}
			}
		})
	}
	if err := Write(&bytes.Buffer{}, "unknown", input, false); err == nil {
		t.Fatal("expected unknown format error")
	}
}

func TestGitLabCodeQualityIncludesWaiverStateAndIdentity(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Remediation: "Fix it.", Severity: sdk.SeverityError}
	finding := sdk.Finding{Message: "Failed", Location: sdk.Location{Path: "demo.yaml", Line: 2}, Waived: true, WaiverID: "demo.reviewed"}
	finding.Finalize(rule)
	finding.Waived = true
	finding.WaiverID = "demo.reviewed"
	finding.State = sdk.FindingWaived
	input := &engine.Report{Project: "demo", Findings: []sdk.Finding{finding}}
	var output bytes.Buffer
	if err := Write(&output, "gitlab-codequality", input, false); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "State: waived.") || !strings.Contains(output.String(), "Waiver: demo.reviewed") {
		t.Fatalf("waiver review state missing: %s", output.String())
	}
}

func TestReportDiffUsesFingerprintAndPolicyDigests(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Remediation: "Fix it.", Severity: sdk.SeverityError}
	first := sdk.Finding{Message: "First", Location: sdk.Location{Path: "a.yaml", Line: 1}}
	first.Finalize(rule)
	changed := first
	changed.Message = "Changed"
	changed.FindingDigest = "sha256:" + strings.Repeat("f", 64)
	added := sdk.Finding{Message: "Added", Location: sdk.Location{Path: "b.yaml", Line: 1}}
	added.Finalize(rule)
	before := &engine.Report{PolicyDigest: "sha256:" + strings.Repeat("a", 64), Findings: []sdk.Finding{first}}
	after := &engine.Report{PolicyDigest: "sha256:" + strings.Repeat("b", 64), Findings: []sdk.Finding{changed, added}}
	diff := Compare(before, after)
	if len(diff.Added) != 1 || len(diff.Removed) != 0 || len(diff.Changed) != 1 || diff.Changed[0].Fingerprint != first.Fingerprint {
		t.Fatalf("unexpected diff: %#v", diff)
	}
	var text bytes.Buffer
	if err := WriteDiff(&text, "text", diff); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "POLICY") || !strings.Contains(text.String(), "1 added, 0 removed, 1 changed") {
		t.Fatalf("unexpected diff text: %s", text.String())
	}
}

func TestReportDiffClassifiesWaiverReviewChanges(t *testing.T) {
	t.Parallel()
	day := func(value string) config.Date {
		parsed, _ := time.Parse("2006-01-02", value)
		return config.Date{Time: parsed}
	}
	before := &engine.Report{GeneratedAt: time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC), Waivers: []config.Waiver{
		{ID: "demo.keep", Fingerprints: []string{"one"}, Paths: []string{"a.yaml"}, Expires: day("2026-08-10")},
		{ID: "demo.remove", Expires: day("2026-08-02")},
	}}
	after := &engine.Report{GeneratedAt: time.Date(2026, 8, 12, 0, 0, 0, 0, time.UTC), Waivers: []config.Waiver{
		{ID: "demo.keep", Fingerprints: []string{"one", "two"}, Paths: []string{"a.yaml", "b.yaml"}, Expires: day("2026-09-10")},
		{ID: "demo.add", Expires: day("2026-08-11")},
	}}
	diff := Compare(before, after)
	if len(diff.Waivers.Added) != 1 || len(diff.Waivers.Removed) != 1 || len(diff.Waivers.Renewed) != 1 || len(diff.Waivers.ScopeGrown) != 1 || len(diff.Waivers.Expired) != 1 {
		t.Fatalf("unexpected waiver diff: %#v", diff.Waivers)
	}
	var output bytes.Buffer
	if err := WriteDiff(&output, "text", diff); err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"WAIVER ADDED", "WAIVER REMOVED", "WAIVER RENEWED", "WAIVER SCOPE-GROWN", "WAIVER EXPIRED"} {
		if !strings.Contains(output.String(), marker) {
			t.Fatalf("missing %s in %s", marker, output.String())
		}
	}
}

func TestJUnitHandlesMissingFingerprint(t *testing.T) {
	t.Parallel()
	input := &engine.Report{Project: "demo", Findings: []sdk.Finding{{RuleID: "raw", Message: "raw"}}}
	if err := Write(&bytes.Buffer{}, "junit", input, false); err != nil {
		t.Fatal(err)
	}
}

func TestTextReportSanitizesControlCharacters(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Remediation: "fix\nnow\x1b[2J", Severity: sdk.SeverityError}
	finding := sdk.Finding{Message: "failed\nFORGED ERROR\x1b[31m", Location: sdk.Location{Path: "bad\npath", Line: 1, Column: 1}}
	finding.Finalize(rule)
	input := &engine.Report{Project: "demo", Findings: []sdk.Finding{finding}, Summary: engine.Summary{Rules: 1, Blocking: 1}}
	var output bytes.Buffer
	if err := Write(&output, "text", input, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "\x1b") || strings.Contains(output.String(), "failed\nFORGED") || strings.Contains(output.String(), "bad\npath") {
		t.Fatalf("control characters reached text report: %q", output.String())
	}
}

func TestGitHubSummaryEscapesUntrustedMarkup(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo", Remediation: "<img src=x onerror=alert(1)>", Severity: sdk.SeverityError}
	finding := sdk.Finding{Message: "<script>alert(1)</script>", Location: sdk.Location{Path: "<unsafe>.yaml", Line: 1}}
	finding.Finalize(rule)
	input := &engine.Report{Project: "demo", Findings: []sdk.Finding{finding}, Summary: engine.Summary{Rules: 1, Blocking: 1}}
	var output bytes.Buffer
	if err := Write(&output, "github", input, false); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(output.String(), "<script>") || strings.Contains(output.String(), "<img") || !strings.Contains(output.String(), "&lt;script&gt;") {
		t.Fatalf("untrusted markup reached GitHub summary: %s", output.String())
	}
}

func TestHistoricalWaiverLoadFailuresBecomeLifecycleFindings(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	project := &config.Project{Project: "demo", Root: root, Waivers: ".hoolicy/waivers.yaml"}
	path := filepath.Join(root, project.Waivers)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("version: 2\nwaivers: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	waivers, lifecycle, err := loadHistoricalWaivers(project, time.Now().UTC(), nil)
	if err != nil || len(waivers) != 0 || len(lifecycle) != 1 || !strings.Contains(lifecycle[0].Message, "version must be 1") {
		t.Fatalf("wrong-version waiver load: waivers=%#v lifecycle=%#v err=%v", waivers, lifecycle, err)
	}
	target := filepath.Join(root, "target.yaml")
	if err := os.WriteFile(target, []byte("version: 1\nwaivers: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	waivers, lifecycle, err = loadHistoricalWaivers(project, time.Now().UTC(), nil)
	if err != nil || len(waivers) != 0 || len(lifecycle) != 1 || !strings.Contains(lifecycle[0].Message, "Waiver path is unsafe") {
		t.Fatalf("unsafe waiver load: waivers=%#v lifecycle=%#v err=%v", waivers, lifecycle, err)
	}
}

func TestHistoricalWaiverMigrationPreservesLegacyScopes(t *testing.T) {
	t.Parallel()
	now := time.Date(2026, 9, 2, 12, 0, 0, 0, time.UTC)
	finding := sdk.Finding{RuleID: "demo.rule", Fingerprint: strings.Repeat("a", 64), Location: sdk.Location{Path: "foo/bar"}}
	for _, path := range []string{`foo\bar`, "**/**"} {
		waiver := config.Waiver{ID: "demo.review", Rule: finding.RuleID, Paths: []string{path}, Reason: "A sufficiently detailed historical reason.", Owner: "team@example.com", Ticket: "https://issues.example.com/DEMO-1", Created: config.Date{Time: now.AddDate(0, 0, -1)}, Expires: config.Date{Time: now.AddDate(0, 0, 10)}}
		if err := validateLegacyWaiver(waiver, now); err != nil {
			t.Fatalf("legacy path %q rejected: %v", path, err)
		}
		migrated, keep := migrateHistoricalWaiver(waiver, []sdk.Finding{finding}, now)
		if !keep || len(migrated.Paths) != 0 || !containsString(migrated.Fingerprints, finding.Fingerprint) {
			t.Fatalf("legacy path %q not preserved safely: %#v keep=%v", path, migrated, keep)
		}
	}
}

func TestHistoricalWaiverReplayUsesFinalFileOrder(t *testing.T) {
	t.Parallel()
	finding := sdk.Finding{RuleID: "demo.rule", Fingerprint: strings.Repeat("a", 64)}
	first := config.Waiver{ID: "demo.first", Rule: finding.RuleID, Fingerprints: []string{finding.Fingerprint}}
	last := config.Waiver{ID: "demo.last", Rule: finding.RuleID, Fingerprints: []string{finding.Fingerprint}}
	state := replayHistoricalWaiverState([]sdk.Finding{finding}, []historicalWaiver{{legacy: first}, {legacy: last}})
	if got := state[finding.Fingerprint]; !got.waived || got.waiverID != "demo.last" {
		t.Fatalf("replayed waiver state=%#v, want final file entry", got)
	}
}

func TestHistoricalWaiverFindingsAreOrderIndependent(t *testing.T) {
	t.Parallel()
	project := &config.Project{Project: "demo", Waivers: ".hoolicy/waivers.yaml"}
	stale := historicalWaiverFinding(project, "Stale waiver matches no current finding: demo.review", "demo.review")
	duplicate := historicalWaiverFinding(project, "Duplicate waiver ID: demo.review", "demo.review")
	findings := []legacyFinding{
		{RuleID: stale.RuleID, Title: stale.Title, Message: stale.Message, Remediation: stale.Remediation, Severity: stale.Severity, Location: stale.Location, Key: stale.Key, Fingerprint: stale.Fingerprint},
		{RuleID: duplicate.RuleID, Title: duplicate.Title, Message: duplicate.Message, Remediation: duplicate.Remediation, Severity: duplicate.Severity, Location: duplicate.Location, Key: duplicate.Key, Fingerprint: duplicate.Fingerprint},
	}
	if err := verifyHistoricalWaiverFindings(findings, []sdk.Finding{duplicate, stale}); err != nil {
		t.Fatal(err)
	}
}
