package policylint

import (
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
