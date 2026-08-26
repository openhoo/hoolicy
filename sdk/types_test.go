package sdk

import (
	"context"
	"testing"
)

func TestFindingFingerprintIsStable(t *testing.T) {
	t.Parallel()
	rule := Rule{ID: "demo.rule", Title: "Demo", Remediation: "Fix", Severity: SeverityWarning, Controls: []Control{{Framework: "SOC2", ID: "CC8.1"}}}
	left := Finding{Location: Location{Path: "a/../a/file.yaml", Line: 2, Column: 3}, Key: "item"}
	right := Finding{Location: Location{Path: "a/file.yaml", Line: 2, Column: 3}, Key: "item"}
	left.Finalize(rule)
	right.Finalize(rule)
	if left.Fingerprint != right.Fingerprint || len(left.Fingerprint) != 64 || left.Severity != SeverityWarning || len(left.Controls) != 1 {
		t.Fatalf("unexpected finalized findings: %#v %#v", left, right)
	}
}

func TestRegistryRejectsDuplicateKinds(t *testing.T) {
	t.Parallel()
	registry := NewRegistry()
	kind := noopKind{}
	if err := registry.Register("noop", kind); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register("noop", kind); err == nil {
		t.Fatal("expected duplicate registration error")
	}
	if names := registry.Names(); len(names) != 1 || names[0] != "noop" {
		t.Fatalf("unexpected names: %#v", names)
	}
}

type noopKind struct{}

func (noopKind) Validate(Rule) error { return nil }
func (noopKind) Evaluate(context.Context, EvalContext, Rule) ([]Finding, error) {
	return nil, nil
}
