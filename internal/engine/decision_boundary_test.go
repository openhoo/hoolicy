package engine_test

import (
	"context"
	"math"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/sdk"
)

type decisionBoundaryKind struct{ finding sdk.Finding }

func (decisionBoundaryKind) Validate(sdk.Rule) error { return nil }
func (kind decisionBoundaryKind) Evaluate(context.Context, sdk.EvalContext, sdk.Rule) ([]sdk.Finding, error) {
	return []sdk.Finding{kind.finding}, nil
}

func decisionBoundaryProject(t *testing.T) *config.Project {
	t.Helper()
	root := t.TempDir()
	path := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, path, `version: 1
project: decisions
failOn: error
rules:
  - id: demo.boundary
    title: Decision boundary
    description: Tests extension finding boundaries.
    rationale: Invalid findings must not acquire a reviewed decision identity.
    remediation: Return valid finding metadata.
    severity: error
    kind: test.boundary
`)
	project, err := config.LoadProject(path)
	if err != nil {
		t.Fatal(err)
	}
	return project
}

func TestEngineRejectsInvalidExtensionFindings(t *testing.T) {
	cycle := map[string]any{}
	cycle["self"] = cycle
	for name, finding := range map[string]sdk.Finding{
		"channel":         {Properties: map[string]any{"value": make(chan int)}},
		"NaN":             {Properties: map[string]any{"value": math.NaN()}},
		"infinity":        {Properties: map[string]any{"value": math.Inf(1)}},
		"cyclic property": {Properties: cycle},
		"negative line":   {Location: sdk.Location{Path: "README.md", Line: -1}},
		"negative column": {Location: sdk.Location{Path: "README.md", Column: -1}},
	} {
		t.Run(name, func(t *testing.T) {
			project := decisionBoundaryProject(t)
			registry := sdk.NewRegistry()
			if err := registry.Register("test.boundary", decisionBoundaryKind{finding}); err != nil {
				t.Fatal(err)
			}
			decision, err := engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
			if err == nil || !strings.Contains(err.Error(), "invalid finding") || decision != nil {
				t.Fatalf("invalid extension finding produced a decision: decisionPresent=%v err=%v", decision != nil, err)
			}
		})
	}

	t.Run("valid properties", func(t *testing.T) {
		project := decisionBoundaryProject(t)
		registry := sdk.NewRegistry()
		finding := sdk.Finding{Message: "violation", Properties: map[string]any{"count": 2, "values": []any{"x", true, nil}}, State: sdk.FindingExisting, Waived: true, WaiverID: "forged"}
		if err := registry.Register("test.boundary", decisionBoundaryKind{finding}); err != nil {
			t.Fatal(err)
		}
		decision, err := engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
		if err != nil || decision.Summary.Blocking != 1 || decision.Findings[0].State != sdk.FindingNew || decision.Findings[0].Waived {
			t.Fatalf("valid extension finding lost blocking state: decision=%v err=%v", decision, err)
		}
	})
}

func TestFutureCreatedWaiverCannotSuppressCurrentFinding(t *testing.T) {
	project := decisionBoundaryProject(t)
	registry := sdk.NewRegistry()
	if err := registry.Register("test.boundary", decisionBoundaryKind{sdk.Finding{Message: "violation"}}); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	first, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	writeEngineFile(t, filepath.Join(project.Root, config.DefaultWaivers), "version: 1\nwaivers:\n  - id: demo.future\n    rule: demo.boundary\n    fingerprints: ["+first.Findings[0].Fingerprint+"]\n    reason: Future review cannot suppress a violation now.\n    owner: team@example.invalid\n    ticket: https://issues.example.invalid/DEMO-1\n    created: 2099-01-01\n    expires: 2099-01-02\n")
	decision, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if decision.Summary.Waived != 0 || decision.Summary.Blocking != 2 || len(decision.Findings) != 2 {
		t.Fatalf("future review suppressed the current finding: summary=%+v findings=%v", decision.Summary, decision.Findings)
	}
	if !strings.Contains(decision.Findings[0].Message+decision.Findings[1].Message, "created must not be in the future") {
		t.Fatalf("future creation lifecycle reason missing: %v", decision.Findings)
	}
}
