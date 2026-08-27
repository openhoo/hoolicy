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
`)
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	result := Run(context.Background(), root, registry)
	if result.Passed != 2 || len(result.Errors) != 0 {
		t.Fatalf("unexpected result: %#v", result)
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
