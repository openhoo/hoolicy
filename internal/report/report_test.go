package report

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

func TestReportFormats(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule", Title: "Demo rule", Remediation: "Fix it.", Severity: sdk.SeverityError}
	finding := sdk.Finding{Message: "Failed", Location: sdk.Location{Path: "demo.yaml", Line: 2, Column: 3}}
	finding.Finalize(rule)
	input := &engine.Report{ReportVersion: 1, Tool: engine.Tool{Name: "hoolicy", Version: "test"}, Project: "demo", Findings: []sdk.Finding{finding}, Summary: engine.Summary{Rules: 1, Errors: 1, Blocking: 1}}
	for _, format := range []string{"text", "json", "sarif", "junit"} {
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
			case "json", "sarif":
				var value any
				if err := json.Unmarshal(output.Bytes(), &value); err != nil {
					t.Fatalf("invalid JSON: %v", err)
				}
			case "junit":
				var value struct {
					XMLName xml.Name `xml:"testsuites"`
				}
				if err := xml.Unmarshal(output.Bytes(), &value); err != nil {
					t.Fatalf("invalid XML: %v", err)
				}
			}
		})
	}
	if err := Write(&bytes.Buffer{}, "unknown", input, false); err == nil {
		t.Fatal("expected unknown format error")
	}
}

func TestJUnitHandlesMissingFingerprint(t *testing.T) {
	t.Parallel()
	input := &engine.Report{Project: "demo", Findings: []sdk.Finding{{RuleID: "raw", Message: "raw"}}}
	if err := Write(&bytes.Buffer{}, "junit", input, false); err != nil {
		t.Fatal(err)
	}
}
