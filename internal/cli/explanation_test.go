package cli

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/diagnostic"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

func TestCheckParsedArgumentDiagnosticsRespectFormat(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hoolicy.yaml")
	writeCLIFile(t, path, "version: 1\nproject: demo\nrules: []\n")
	for _, test := range []struct {
		name string
		args []string
		json bool
	}{
		{"positional", []string{"--format", "json", "unexpected"}, true},
		{"text override", []string{"--format", "json", "--error-format", "text", "unexpected"}, false},
		{"json override", []string{"--error-format", "json", "unexpected"}, true},
		{"invalid report format", []string{"--format", "bad", "--error-format", "json"}, true},
		{"invalid error format", []string{"--format", "json", "--error-format", "bad"}, true},
		{"invalid threshold", []string{"--format", "json", "--fail-on", "bad"}, true},
	} {
		t.Run(test.name, func(t *testing.T) {
			app, stdout, stderr := testApplication(t)
			args := append([]string{"check", "--config", path}, test.args...)
			if code := app.run(context.Background(), args); code != 2 || stdout.Len() != 0 {
				t.Fatalf("code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
			}
			if test.json {
				var envelope struct {
					Error diagnostic.Diagnostic `json:"error"`
				}
				if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil || envelope.Error.Phase != "arguments" || envelope.Error.Code != "arguments_failed" || envelope.Error.ExitCode != 2 {
					t.Fatalf("invalid argument diagnostic: %v %s", err, stderr.String())
				}
			} else if !strings.Contains(stderr.String(), "Phase: arguments") || !strings.Contains(stderr.String(), "hoolicy check --help") {
				t.Fatalf("argument guidance missing: %s", stderr.String())
			}
		})
	}
	// The flag parser's own usage/help remains text, even when JSON was requested.
	for _, argument := range []string{"--unknown-flag", "--help"} {
		app, _, stderr := testApplication(t)
		code := app.run(context.Background(), []string{"check", "--format", "json", argument})
		expected := 2
		if argument == "--help" {
			expected = 0
		}
		if code != expected || json.Valid(stderr.Bytes()) || !strings.Contains(stderr.String(), "Usage of check") {
			t.Fatalf("flag parser contract changed: code=%d %s", code, stderr.String())
		}
	}
}

func TestCheckOutputDiagnosticsPreservePolicyInputs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "hoolicy.yaml")
	policy := "version: 1\nproject: demo\nrules: []\n"
	writeCLIFile(t, path, policy)
	for _, destination := range []string{path, root} {
		app, stdout, stderr := testApplication(t)
		if code := app.run(context.Background(), []string{"check", "--config", path, "--format", "json", "--output", destination}); code != 2 || stdout.Len() != 0 {
			t.Fatalf("invalid output was accepted: code=%d %s", code, stderr.String())
		}
		var envelope struct {
			Error diagnostic.Diagnostic `json:"error"`
		}
		if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil || envelope.Error.Phase != "output" || envelope.Error.Code != "output_failed" {
			t.Fatalf("output failure lost its phase: %v %s", err, stderr.String())
		}
		data, err := os.ReadFile(path)
		if err != nil || string(data) != policy {
			t.Fatal("output error altered protected policy input")
		}
	}
}

func TestCheckOutputWriteFailuresRemainOperationalJSON(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hoolicy.yaml")
	writeCLIFile(t, path, "version: 1\nproject: demo\nrules: []\n")
	for _, writer := range []io.Writer{shortCLIWriter{}, failingCLIWriter{}} {
		app, _, stderr := testApplication(t)
		app.stdout = writer
		if code := app.run(context.Background(), []string{"check", "--config", path, "--format", "json"}); code != 2 {
			t.Fatalf("failed output returned %d", code)
		}
		var envelope struct {
			Error diagnostic.Diagnostic `json:"error"`
		}
		if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil || envelope.Error.Phase != "output" || envelope.Error.ExitCode != 2 {
			t.Fatalf("output writer failure lost machine diagnostics: %v %s", err, stderr.String())
		}
	}
}

const explanationProject = `version: 1
project: explanation-demo
rules:
  - id: demo.enabled
    title: Configuration must be enabled
    description: Checks the enabled setting in service configuration.
    rationale: Disabled configuration prevents service startup.
    remediation: Review the configuration and set enabled to true.
    severity: error
    kind: structured.cel
    files: [input.json]
    explanation:
      expectation: enabled must be true.
      impact: The service cannot start with this configuration.
      steps:
        - Review input.json with the service owner.
        - Enable the setting and rerun the check.
      references:
        - title: Configuration guide
          url: https://example.invalid/configuration#enabled
    spec:
      format: json
      expression: documents.all(d, d.data.enabled == true)
      message: The enabled setting is false
`

func TestCLIExplainsViolationsAcrossDiscoveryAndReports(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "hoolicy.yaml")
	writeCLIFile(t, path, explanationProject)
	writeCLIFile(t, filepath.Join(root, "input.json"), `{"enabled":false}`)
	for _, command := range []string{"check", "explain", "list", "inventory"} {
		for _, format := range []string{"text", "json"} {
			if command == "inventory" && format == "text" {
				continue
			}
			args := []string{command, "--config", path}
			if command != "inventory" {
				args = append(args, "--format", format)
			}
			if command == "explain" {
				args = append(args, "demo.enabled")
			}
			app, stdout, stderr := testApplication(t)
			code := app.run(context.Background(), args)
			expected := 0
			if command == "check" {
				expected = 1
			}
			if code != expected || stderr.Len() > 0 {
				t.Fatalf("%v: code=%d stderr=%s", args, code, stderr.String())
			}
			if command != "list" || format == "json" {
				for _, text := range []string{"enabled must be true.", "Disabled configuration prevents service startup.", "Configuration guide"} {
					if !strings.Contains(stdout.String(), text) {
						t.Errorf("%v omits %q: %s", args, text, stdout.String())
					}
				}
			}
			if format == "json" && !json.Valid(stdout.Bytes()) {
				t.Fatalf("%v emitted invalid JSON: %s", args, stdout.String())
			}
			if command == "check" && format == "json" {
				var result engine.Report
				if err := json.Unmarshal(stdout.Bytes(), &result); err != nil || result.Findings[0].Policy.Explanation.Expectation != "enabled must be true." {
					t.Fatalf("policy context was lost: %v", err)
				}
			}
		}
	}
}

func TestCheckOperationalDiagnosticsPreserveExitAndDestination(t *testing.T) {
	t.Parallel()
	for _, failure := range []string{"configuration", "validation", "evaluation"} {
		for _, format := range []string{"text", "json", "sarif"} {
			root := t.TempDir()
			path := filepath.Join(root, "hoolicy.yaml")
			policy := explanationProject
			input := `{"enabled":false}`
			switch failure {
			case "configuration":
				policy += "unknownField: true\n"
			case "validation":
				policy = strings.Replace(policy, "d.data.enabled == true", "invalidSyntax(", 1)
			case "evaluation":
				input = "{malformed"
			}
			writeCLIFile(t, path, policy)
			writeCLIFile(t, filepath.Join(root, "input.json"), input)
			destination := filepath.Join(root, "report.json")
			writeCLIFile(t, destination, "existing report bytes")
			args := []string{"check", "--config", path, "--format", format, "--output", destination}
			if format == "sarif" {
				args = append(args, "--error-format", "json")
			}
			app, stdout, stderr := testApplication(t)
			if code := app.run(context.Background(), args); code != 2 || stdout.Len() != 0 {
				t.Fatalf("%v: code=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
			}
			data, err := os.ReadFile(destination)
			if err != nil || string(data) != "existing report bytes" {
				t.Fatal("failed evaluation replaced a previous decision report")
			}
			if format == "text" {
				if !strings.Contains(stderr.String(), "Phase: "+failure) || failure != "configuration" && !strings.Contains(stderr.String(), "Expected: enabled must be true.") {
					t.Fatalf("failure context omitted: %s", stderr.String())
				}
			} else {
				var envelope struct {
					Version int                   `json:"diagnosticVersion"`
					Error   diagnostic.Diagnostic `json:"error"`
				}
				if err := json.Unmarshal(stderr.Bytes(), &envelope); err != nil || envelope.Version != 1 || envelope.Error.ExitCode != 2 || envelope.Error.Phase != failure {
					t.Fatalf("invalid diagnostic envelope: %v %s", err, stderr.String())
				}
				if failure != "configuration" && (envelope.Error.RuleID != "demo.enabled" || envelope.Error.Policy.Explanation.Expectation != "enabled must be true.") {
					t.Fatalf("diagnostic lost rule guidance: %+v", envelope.Error)
				}
			}
		}
	}
}

func TestJSONListWithoutRulesIsAnArray(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "hoolicy.yaml")
	writeCLIFile(t, path, "version: 1\nproject: empty\nrules: []\n")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"list", "--config", path, "--format", "json"}); code != 0 || strings.TrimSpace(stdout.String()) != "[]" {
		t.Fatalf("empty list: %d %s %s", code, stdout.String(), stderr.String())
	}
}

func TestExplanationsStayStrict(t *testing.T) {
	t.Parallel()
	for _, field := range []string{"unknown: true", "expectation: good\n      expectation: duplicate", "steps: [valid, '']"} {
		path := filepath.Join(t.TempDir(), "hoolicy.yaml")
		policy := strings.Replace(explanationProject, "expectation: enabled must be true.", field, 1)
		writeCLIFile(t, path, policy)
		app, _, stderr := testApplication(t)
		if code := app.run(context.Background(), []string{"validate", "--config", path}); code != 2 {
			t.Fatalf("invalid explanation accepted: %q %s", field, stderr.String())
		}
	}
}

func TestPackCompareIncludesExplanationChanges(t *testing.T) {
	t.Parallel()
	previous := &config.Pack{Rules: []sdk.Rule{{ID: "demo.rule", Title: "Demo"}}}
	current := &config.Pack{Rules: []sdk.Rule{{ID: "demo.rule", Title: "Demo", Explanation: &sdk.Explanation{Expectation: "Reviewed input"}}}}
	diff := comparePackRules(previous, current)
	if len(diff.MetadataChanged) != 1 || diff.MetadataChanged[0] != "demo.rule explanation changed" || len(diff.BehaviorChanged) != 0 {
		t.Fatalf("explanation change was not reviewable: %+v", diff)
	}
}
