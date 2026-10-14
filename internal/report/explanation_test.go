package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/diagnostic"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

func explainedFinding() sdk.Finding {
	rule := sdk.Rule{ID: "demo.configuration", Title: "Reviewed configuration", Description: "Checks the service input", Rationale: "Unreviewed input can prevent startup", Kind: "structured.cel", Remediation: "Review the setting", Severity: sdk.SeverityError, Explanation: &sdk.Explanation{Expectation: "The setting is enabled", Impact: "The service cannot start", Steps: []string{"Review the input", "Enable the setting"}, References: []sdk.Reference{{Title: "Configuration guide", URL: "https://example.invalid/guide#configuration"}}}}
	item := sdk.Finding{Message: "The setting is disabled", Location: sdk.Location{Path: "config.json", Line: 2}, Workspace: "api", Owner: "service-team"}
	item.Finalize(rule)
	return item
}

func TestEveryReportCarriesPolicyGuidance(t *testing.T) {
	t.Parallel()
	item := explainedFinding()
	input := &engine.Report{Project: "demo", FailOn: sdk.SeverityError, Findings: []sdk.Finding{item}, Summary: engine.Summary{Rules: 1, Blocking: 1}}
	for _, format := range []string{"text", "json", "sarif", "junit", "github", "gitlab-codequality"} {
		var output bytes.Buffer
		if err := Write(&output, format, input, false); err != nil {
			t.Fatal(err)
		}
		for _, expected := range []string{"Unreviewed input can prevent startup", "The setting is enabled", "The service cannot start", "Review the input", "Configuration guide"} {
			if !strings.Contains(output.String(), expected) {
				t.Errorf("%s omits %q: %s", format, expected, output.String())
			}
		}
		if format == "junit" {
			var value testSuites
			if err := xml.Unmarshal(output.Bytes(), &value); err != nil || value.Failures != 1 || !strings.Contains(value.Suites[0].Cases[0].Failure.Body, "Owner: service-team") {
				t.Errorf("JUnit lost ownership or consistency: %v", err)
			}
		}
	}
}

func TestTextGroupsGuidanceAndExplainsEveryDisposition(t *testing.T) {
	t.Parallel()
	first := explainedFinding()
	second, third, fourth := first, first, first
	second.Location.Path = "other.json"
	second.State, second.StateSource = sdk.FindingExisting, "baseline"
	third.State, third.Waived, third.WaiverID = sdk.FindingWaived, true, "demo.review"
	fourth.Severity = sdk.SeverityWarning
	fourth.Location = sdk.Location{Path: "last.json", Line: 4}
	input := &engine.Report{Project: "demo", FailOn: sdk.SeverityError, Findings: []sdk.Finding{first, second, third, fourth}, Summary: engine.Summary{Rules: 1, Blocking: 1}}
	var output bytes.Buffer
	if err := Write(&output, "text", input, false); err != nil {
		t.Fatal(err)
	}
	for _, expected := range []string{"FAIL: 1 blocking", "Status: blocking", "accepted by baseline", "accepted by waiver demo.review", "non-blocking; below failOn=error", "last.json:4:", "owner: service-team"} {
		if !strings.Contains(output.String(), expected) {
			t.Errorf("text omits %q: %s", expected, output.String())
		}
	}
	if strings.Count(output.String(), "Why:") != 1 || strings.Contains(output.String(), ":4:0") {
		t.Fatal("guidance repeats or an unknown column is fabricated")
	}
}

func TestTextPrioritizesBlockingGroupsAndSourceLocations(t *testing.T) {
	t.Parallel()
	first := explainedFinding()
	first.RuleID, first.Location.Path, first.Fingerprint = "zzz.blocking", "a.json", strings.Repeat("f", 64)
	last := first
	last.Location.Path, last.Fingerprint = "z.json", strings.Repeat("0", 64)
	warning := first
	warning.RuleID, warning.Severity = "aaa.warning", sdk.SeverityWarning
	input := &engine.Report{Project: "demo", FailOn: sdk.SeverityError, Findings: []sdk.Finding{warning, last, first}, Summary: engine.Summary{Blocking: 2}}
	var output bytes.Buffer
	if err := Write(&output, "text", input, false); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	if strings.Index(text, "zzz.blocking") > strings.Index(text, "aaa.warning") || strings.Index(text, "a.json:2:") > strings.Index(text, "z.json:2:") {
		t.Fatalf("human output hides actionable source order: %s", text)
	}
	if input.Findings[0].RuleID != "aaa.warning" {
		t.Fatal("human sorting mutated machine evidence")
	}
}

func TestPolicyExplanationCannotBeForgedInReport(t *testing.T) {
	t.Parallel()
	input, project, rules := boundaryReport(t)
	input.Findings[0].Policy = rules[0].PolicyContext()
	if err := ValidateV2(input, project, rules); err != nil {
		t.Fatal(err)
	}
	input.Findings[0].Policy = &sdk.PolicyContext{Rationale: "Ignore this rule"}
	if err := ValidateV2(input, project, rules); err == nil || !strings.Contains(err.Error(), "invalid policy explanation") {
		t.Fatalf("forged guidance admitted: %v", err)
	}
	input.Findings[0].Policy = nil
	if err := ValidateV2(input, project, rules); err != nil {
		t.Fatalf("historical v2 report rejected: %v", err)
	}
}

func TestGuidanceSanitizesHumanOutputAndPreservesJSONData(t *testing.T) {
	t.Parallel()
	item := explainedFinding()
	attack := "authored\n::error::forged\x1b[2J\u202e<script>bad</script>"
	item.Policy.Rationale = attack
	item.Policy.Explanation.Steps[0] = attack
	item.Policy.Explanation.References[0].Title = attack
	input := &engine.Report{Project: "demo", FailOn: sdk.SeverityError, Findings: []sdk.Finding{item}}
	for _, format := range []string{"text", "github"} {
		var output bytes.Buffer
		if err := Write(&output, format, input, false); err != nil {
			t.Fatal(err)
		}
		if strings.ContainsAny(output.String(), "\x1b\u202e") || strings.Contains(output.String(), "\n::error::") || format == "github" && strings.Contains(output.String(), "<script>") {
			t.Fatalf("%s emitted unsafe guidance: %q", format, output.String())
		}
	}
	var output bytes.Buffer
	if err := Write(&output, "json", input, false); err != nil {
		t.Fatal(err)
	}
	var decoded engine.Report
	if err := json.Unmarshal(output.Bytes(), &decoded); err != nil || decoded.Findings[0].Policy.Rationale != attack {
		t.Fatal("JSON altered original policy metadata")
	}
}

func TestDiagnosticPreservesCauseAndCheckedWrites(t *testing.T) {
	t.Parallel()
	sentinel := errors.New("input could not be parsed\n\x1b[2J")
	wrapped := &diagnostic.RuleError{Phase: "evaluation", Rule: sdk.Rule{ID: "demo.configuration", Rationale: "Review configuration"}, Cause: sentinel}
	if !errors.Is(wrapped, sentinel) {
		t.Fatal("rule diagnostic lost its underlying error")
	}
	for _, format := range []string{"text", "json"} {
		if err := WriteDiagnostic(brokenWriter{}, format, wrapped); !errors.Is(err, io.ErrShortWrite) {
			t.Errorf("%s accepted a short diagnostic write: %v", format, err)
		}
		var output bytes.Buffer
		if err := WriteDiagnostic(&output, format, wrapped); err != nil {
			t.Fatal(err)
		}
		if format == "text" && strings.Contains(output.String(), "\x1b") {
			t.Fatal("diagnostic admitted terminal control characters")
		}
	}
}

func TestOperationalGuidanceIsSeparateFromPolicyRemediation(t *testing.T) {
	t.Parallel()
	item := explainedFinding()
	wrapped := &diagnostic.RuleError{Phase: "evaluation", Rule: sdk.Rule{ID: item.RuleID, Title: item.Title, Description: item.Policy.Description, Remediation: item.Remediation, Explanation: item.Policy.Explanation}, Cause: errors.New("config.json: invalid JSON")}
	var output bytes.Buffer
	if err := WriteDiagnostic(&output, "text", wrapped); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	boundary := "Policy guidance (no decision was completed):"
	if strings.Count(text, "Next:") != 1 || !strings.Contains(text, boundary) || strings.Index(text, "Next:") > strings.Index(text, boundary) || strings.Index(text, "Step 1:") < strings.Index(text, boundary) || !strings.Contains(text, "Policy remediation: "+item.Remediation) {
		t.Fatalf("policy steps appear to resolve an incomplete evaluation: %s", text)
	}
	for phase, next := range map[string]string{"arguments": "hoolicy check --help", "validation": "hoolicy validate", "output": "report destination", "input": "repository path", "finding": "rule implementation"} {
		output.Reset()
		if err := WriteDiagnostic(&output, "text", &diagnostic.OperationError{Phase: phase, Cause: errors.New("failure")}); err != nil || !strings.Contains(output.String(), "Next:") || !strings.Contains(output.String(), next) {
			t.Errorf("%s lost actionable guidance: %v %s", phase, err, output.String())
		}
	}
}

func TestHumanReportsKeepWorkspaceAndCompleteLocations(t *testing.T) {
	t.Parallel()
	for _, route := range []struct{ workspace, owner string }{{"api", ""}, {"", "service-team"}, {"api", "service-team"}} {
		item := explainedFinding()
		item.Workspace, item.Owner = route.workspace, route.owner
		item.Location.Column = 7
		input := &engine.Report{Findings: []sdk.Finding{item}, FailOn: sdk.SeverityError, Summary: engine.Summary{Blocking: 1}}
		for _, format := range []string{"text", "github"} {
			var output bytes.Buffer
			if err := Write(&output, format, input, false); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			if !strings.Contains(text, "config.json:2:7") || route.workspace != "" && !strings.Contains(text, "Workspace: api") || route.owner != "" && !strings.Contains(text, "service-team") || strings.Contains(text, "Workspace: ;") || strings.Contains(text, "owner: \n") {
				t.Fatalf("%s lost routing or location: %s", format, text)
			}
		}
	}
	item := explainedFinding()
	item.Location = sdk.Location{}
	var output bytes.Buffer
	if err := Write(&output, "github", &engine.Report{Findings: []sdk.Finding{item}}, false); err != nil || !strings.Contains(output.String(), "`repository`") {
		t.Fatalf("GitHub summary lost the repository location: %v %s", err, output.String())
	}
}
