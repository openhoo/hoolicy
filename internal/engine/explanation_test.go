package engine_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/diagnostic"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/report"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestFindingBudgetFailureRetainsActiveRuleContext(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), config.DefaultFilename)
	writeEngineFile(t, path, `version: 1
project: finding-budget
budgets:
  maximumFindings: 1
rules:
  - id: demo.required
    title: Production debug disabled
    description: Requires debug to be disabled in both service configurations.
    rationale: Production configuration must be reviewed.
    remediation: Disable debug in the reported service configuration.
    severity: error
    kind: structured.fields
    files: [first.yaml, second.yaml]
    explanation:
      expectation: Both service configurations disable debug.
    spec:
      format: yaml
      fields:
        - pointer: /debug
          required: true
          type: boolean
          allowedValues: [false]
`)
	for _, name := range []string{"first.yaml", "second.yaml"} {
		writeEngineFile(t, filepath.Join(filepath.Dir(path), name), "debug: true\n")
	}
	project, err := config.LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	decision, err := engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	var ruleError *diagnostic.RuleError
	if decision != nil || !errors.As(err, &ruleError) || ruleError.Phase != "finding" || ruleError.Rule.ID != "demo.required" {
		t.Fatalf("finding budget lost active rule context: %v", err)
	}
	if detail := diagnostic.Describe(err); detail.Policy.Explanation.Expectation != "Both service configurations disable debug." {
		t.Fatal("finding budget omitted authored policy guidance")
	}
}

func TestTotalBudgetFailureRetainsActiveRuleContext(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), config.DefaultFilename)
	writeEngineFile(t, path, `version: 1
project: timeout
budgets:
  maximumRuleDuration: 2s
  maximumTotalDuration: 200ms
rules:
  - id: timeout.blocking
    title: Blocking rule
    description: Simulates an uncooperative extension.
    rationale: Engine deadlines must remain authoritative.
    remediation: Make the extension honor cancellation.
    severity: error
    kind: test.blocking
    explanation:
      expectation: Evaluation completes within the total budget.
`)
	project, err := config.LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	defer close(release)
	registry := sdk.NewRegistry()
	if err := registry.Register("test.blocking", blockingRule{release: release}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	var ruleError *diagnostic.RuleError
	if result != nil || !errors.Is(err, context.DeadlineExceeded) || !errors.As(err, &ruleError) || ruleError.Rule.ID != "timeout.blocking" || ruleError.Phase != "evaluation" {
		t.Fatalf("total deadline lost active rule context: %v", err)
	}
	if detail := diagnostic.Describe(err); detail.Policy.Explanation.Expectation != "Evaluation completes within the total budget." {
		t.Fatal("deadline omitted policy guidance")
	}
}

func TestStandaloneDecisionSatisfiesReportContract(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), config.DefaultFilename)
	writeEngineFile(t, path, "version: 1\nproject: standalone\nrules: []\n")
	project, err := config.LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := engine.New(sdk.NewRegistry()).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if err := report.ValidateV2(decision, project, nil); err != nil {
		t.Fatalf("standalone decision violates the machine report contract: %v", err)
	}
}
