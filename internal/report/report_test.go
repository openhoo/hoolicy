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
