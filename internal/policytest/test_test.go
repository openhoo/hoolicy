package policytest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestBuiltInPacksHavePassingPositiveAndNegativeCases(t *testing.T) {
	t.Setenv("PATH", "")
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"repository", "supply-chain", "product-quality"} {
		t.Run(name, func(t *testing.T) {
			result := Run(context.Background(), filepath.Join("..", "..", "packs", name), registry)
			if len(result.Errors) > 0 || result.Passed != result.Cases || result.Cases < 2 {
				t.Fatalf("unexpected pack test result: %#v", result)
			}
		})
	}
}

func TestWarningRuleFixturesEvaluateRuleOutcome(t *testing.T) {
	root := t.TempDir()
	writePolicyTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.0.0
description: Demo pack.
rules:
  - id: demo.readme
    title: README exists
    description: Requires documentation.
    rationale: Contributors need context.
    remediation: Add README.md.
    severity: warning
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`)
	writePolicyTestFile(t, filepath.Join(root, "tests", "cases.yaml"), `version: 1
cases:
  - {name: present, rule: demo.readme, outcome: pass, files: {README.md: ok}}
  - {name: absent, rule: demo.readme, outcome: fail, files: {}}
  - name: waived absence passes with precise assertion
    rule: demo.readme
    outcome: pass
    files: {}
    now: 2026-01-15T00:00:00Z
    waiveFindings: true
    findingCount: 1
    expect:
      - messageContains: missing
        waived: true
`)
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), root, registry)
	if result.Passed != 3 || len(result.Errors) != 0 {
		t.Fatalf("unexpected result: %#v", result)
	}
}

func TestPreciseFixturesSupportGitClockMultiDocumentAndExpectedErrors(t *testing.T) {
	root := t.TempDir()
	writePolicyTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.0.0
description: Demo structured pack.
rules:
  - id: demo.documents
    title: Documents are ready
    description: Checks deterministic fixture context.
    rationale: Pack behavior must be reproducible.
    remediation: Supply two enabled documents from a clean branch.
    severity: error
    kind: structured.cel
    files: [values.yaml]
    spec:
      expression: documents.size() == 2 && documents.all(d, d.data.enabled == true) && git.branch == 'release/test' && git.dirty == false && now == timestamp('2026-02-03T04:05:06Z')
      message: fixture context mismatch
`)
	writePolicyTestFile(t, filepath.Join(root, "tests", "cases.yaml"), `version: 1
cases:
  - name: deterministic multi document context passes
    rule: demo.documents
    outcome: pass
    branch: release/test
    now: 2026-02-03T04:05:06Z
    documents:
      values.yaml:
        - 'enabled: true'
        - 'enabled: true'
    findingCount: 0
  - name: wrong Git context fails precisely
    rule: demo.documents
    outcome: fail
    branch: feature/test
    now: 2026-02-03T04:05:06Z
    documents:
      values.yaml:
        - 'enabled: true'
        - 'enabled: true'
    findingCount: 1
    expect:
      - key: cel
        messageContains: context mismatch
        waived: false
        hasFix: false
  - name: malformed structured input fails closed
    rule: demo.documents
    outcome: error
    branch: release/test
    now: 2026-02-03T04:05:06Z
    files:
      values.yaml: '[invalid'
    errorContains: values.yaml
`)
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), root, registry)
	if result.Passed != 3 || len(result.Errors) != 0 {
		t.Fatalf("unexpected precise fixture result: %#v", result)
	}
	snapshot, err := BuildSnapshot(context.Background(), root, registry)
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Cases) != 3 || snapshot.Cases[1].RuleID != "demo.documents" {
		t.Fatalf("unexpected snapshot: %#v", snapshot)
	}
}

func TestFixtureCannotUseHarnessFindingAsNegativeCoverage(t *testing.T) {
	root := t.TempDir()
	writePolicyTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.0.0
description: Demo pack.
rules:
  - id: demo.readme
    title: README exists
    description: Requires documentation.
    rationale: Contributors need context.
    remediation: Add README.md.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`)
	writePolicyTestFile(t, filepath.Join(root, "tests", "cases.yaml"), `version: 1
cases:
  - {name: present, rule: demo.readme, outcome: pass, files: {README.md: ok}}
  - name: forged failure
    rule: demo.readme
    outcome: fail
    files:
      README.md: ok
      .hoolicy/waivers.yaml: "invalid: true"
`)
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), root, registry)
	if len(result.Errors) == 0 || !strings.Contains(strings.Join(result.Errors, "\n"), "reserved for the test harness") {
		t.Fatalf("expected reserved fixture rejection, got %#v", result)
	}
}

func writePolicyTestFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
