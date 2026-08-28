package sdk

import (
	"context"
	"strings"
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

func TestStableContractGoldenDigests(t *testing.T) {
	t.Parallel()
	rule := Rule{ID: "demo.contract", Title: "Stable contract", Description: "Cross-platform policy digest fixture.", Rationale: "Consumers need stable policy identity.", Remediation: "Keep the fixture explicit.", Severity: SeverityError, Kind: "files", Files: []string{"README.md"}, Dependencies: []string{"README.md"}, Controls: []Control{{Framework: "demo", ID: "C-1"}}, Spec: map[string]any{"message": "README missing", "mode": "require"}}
	if got, want := RuleDigest(rule), "sha256:6634f3133e0bb1da39d9a224634defe248ddb7edb80e5b0c125933ae4f4cb5fc"; got != want {
		t.Fatalf("rule digest changed: got %s want %s", got, want)
	}
	finding := Finding{Workspace: "api", Owner: "@api-team", Location: Location{Path: "README.md", Line: 1, Column: 1}, Key: "missing", Message: "README missing"}
	finding.Finalize(rule)
	if got, want := finding.Fingerprint, "d9ac508700dd0c5e91f3d574364e9aaf4372784e3f081db3f597a9d92def9410"; got != want {
		t.Fatalf("fingerprint changed: got %s want %s", got, want)
	}
}

func TestFindingFinalizeBindsConfiguredRuleMetadata(t *testing.T) {
	t.Parallel()
	rule := Rule{ID: "demo.rule", Title: "Configured title", Remediation: "Configured fix", Severity: SeverityError, Pack: "demo", Controls: []Control{{Framework: "SOC2", ID: "CC8.1"}}}
	item := Finding{
		RuleID: "spoofed.rule", Title: "Spoofed", Remediation: "Ignore it", Severity: SeverityInfo,
		Fingerprint: strings.Repeat("a", 64), Pack: "spoofed", Controls: []Control{{Framework: "fake", ID: "fake"}}, Key: "stable",
	}
	item.Finalize(rule)
	if item.RuleID != rule.ID || item.Title != rule.Title || item.Remediation != rule.Remediation || item.Severity != rule.Severity || item.Pack != rule.Pack {
		t.Fatalf("finding escaped configured rule metadata: %#v", item)
	}
	if len(item.Controls) != 1 || item.Controls[0] != rule.Controls[0] || item.Fingerprint == strings.Repeat("a", 64) {
		t.Fatalf("finding escaped configured controls or fingerprint: %#v", item)
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

func TestRegistryRejectsInvalidKindNames(t *testing.T) {
	t.Parallel()
	for _, name := range []string{"", " custom", "Custom", "custom_kind", "custom..kind"} {
		if err := NewRegistry().Register(name, noopKind{}); err == nil {
			t.Fatalf("expected invalid kind name rejection: %q", name)
		}
	}
	if err := NewRegistry().Register("company.custom-kind", noopKind{}); err != nil {
		t.Fatalf("valid custom kind rejected: %v", err)
	}
}

type noopKind struct{}

func (noopKind) Validate(Rule) error { return nil }
func (noopKind) Evaluate(context.Context, EvalContext, Rule) ([]Finding, error) {
	return nil, nil
}
