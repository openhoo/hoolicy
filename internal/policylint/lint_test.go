package policylint

import (
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/sdk"
)

func TestPackLintExplainsHeuristicsAndNarrowDisable(t *testing.T) {
	t.Parallel()
	pack := &config.Pack{
		Parameters: map[string]config.Parameter{"unused": {Type: "string", Description: "Unused test parameter."}},
		Rules: []sdk.Rule{
			{ID: "demo.first", Remediation: "fix", Kind: "text", Files: []string{"**/*", "**/*.json"}, Spec: map[string]any{"require": []any{"name"}}},
			{ID: "demo.second", Remediation: "Apply reviewed repository correction.", Kind: "text", Files: []string{"**/*", "**/*.json"}, Spec: map[string]any{"require": []any{"name"}}},
		},
	}
	findings := Pack(pack, nil, nil)
	if len(findings) < 5 {
		t.Fatalf("expected explained heuristic coverage, got %#v", findings)
	}
	disabled := Pack(pack, nil, []string{"weak-remediation:demo.first"})
	for _, finding := range disabled {
		if finding.Check == "weak-remediation" && finding.Scope == "demo.first" {
			t.Fatal("narrow disable was ignored")
		}
	}
}

func TestSeverityIncreaseIsExplicitCompatibilityFinding(t *testing.T) {
	t.Parallel()
	previous := &config.Pack{Rules: []sdk.Rule{{ID: "demo.rule", Severity: sdk.SeverityWarning}}}
	current := &config.Pack{Rules: []sdk.Rule{{ID: "demo.rule", Severity: sdk.SeverityError}}}
	findings := Pack(current, previous, nil)
	found := false
	for _, finding := range findings {
		if finding.Check == "severity-increase" {
			found = true
		}
	}
	if !found {
		t.Fatalf("severity increase was not reported: %#v", findings)
	}
}

func unusedParameters(findings []Finding) map[string]bool {
	result := map[string]bool{}
	for _, finding := range findings {
		if finding.Check == "unused-parameter" {
			result[strings.TrimPrefix(finding.Scope, "parameter:")] = true
		}
	}
	return result
}

func TestUnusedParameterRecognizesCELPackReads(t *testing.T) {
	t.Parallel()
	parameters := map[string]config.Parameter{
		"minimum":     {Type: "number", Description: "Read through field selection."},
		"environment": {Type: "string", Description: "Read through constant index."},
		"optional":    {Type: "string", Description: "Read through a presence test."},
		"placeholder": {Type: "string_list", Description: "Read through a placeholder."},
		"unread":      {Type: "string", Description: "Declared but never read."},
		"mentioned":   {Type: "string", Description: "Only appears as text."},
	}
	cel := func(expression string) sdk.Rule {
		return sdk.Rule{ID: "demo.cel", Remediation: "Apply the reviewed configuration value.", Kind: "structured.cel", Files: []string{"a.json"}, Spec: map[string]any{"expression": expression, "message": "m"}}
	}
	pack := &config.Pack{Parameters: parameters, Rules: []sdk.Rule{
		cel("documents.all(d, d.data.replicas >= pack.minimum && d.data.env == pack['environment'] && (!has(pack.optional) || d.path != 'mentioned') && params.unread == 1 && [1].all(pack, pack > 0))"),
		{ID: "demo.files", Remediation: "Add the required repository files.", Kind: "files", Files: []string{"{{ placeholder }}"}, Spec: map[string]any{"mode": "require"}},
	}}
	unused := unusedParameters(Pack(pack, nil, nil))
	if len(unused) != 2 || !unused["unread"] || !unused["mentioned"] {
		t.Fatalf("unexpected unused parameters: %v", unused)
	}
	pack.Rules = append(pack.Rules, cel("documents.all(d, d.data.key in pack && pack[d.data.key] != '')"))
	if unused := unusedParameters(Pack(pack, nil, nil)); len(unused) != 0 {
		t.Fatalf("dynamic pack access must not report parameters as unused: %v", unused)
	}
}
