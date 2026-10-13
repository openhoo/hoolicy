package policytest

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestBuiltInPacksHavePassingPositiveAndNegativeCases(t *testing.T) {
	t.Setenv("PATH", "")
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	packFiles, err := filepath.Glob(filepath.Join("..", "..", "packs", "*", "pack.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if len(packFiles) == 0 {
		t.Fatal("no built-in policy packs found")
	}
	for _, packFile := range packFiles {
		name := filepath.Base(filepath.Dir(packFile))
		t.Run(name, func(t *testing.T) {
			result := Run(context.Background(), filepath.Dir(packFile), registry)
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

func TestFixturePathsArePortable(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"C:/outside", `C:\outside`, "/outside", `..\outside`, "../outside", " path", "a/../b", "a/./b", "a//b"} {
		if clean, err := safeFixturePath(path); err == nil {
			t.Fatalf("accepted unsafe fixture path %q as %q", path, clean)
		}
	}
	for _, path := range []string{"README.md", "fixtures/service/config.yaml"} {
		if clean, err := safeFixturePath(path); err != nil || clean != filepath.FromSlash(path) {
			t.Fatalf("rejected fixture path %q as %q: %v", path, clean, err)
		}
	}
}

func TestInvalidHarnessFixturesCannotPassAsExpectedEvaluationErrors(t *testing.T) {
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, fixture, message string
	}{
		{"parent path", "files: {../outside.md: content}", "fixture path escapes root"},
		{"absolute path", "files: {/outside.md: content}", "fixture path must be relative"},
		{"windows volume", "files: {C:/outside.md: content}", "fixture path must be relative"},
		{"noncanonical path", "files: {sub/../outside.md: content}", "fixture path must be canonical"},
		{"reserved project", "files: {hoolicy.yaml: content}", "reserved for the test harness"},
		{"reserved waiver", "files: {.hoolicy/waivers.yaml: content}", "reserved for the test harness"},
		{"reserved vendor", "files: {.hoolicy/vendor/demo/pack.yaml: content}", "reserved for the test harness"},
		{"reserved vendor root", "files: {.hoolicy/vendor: content}", "reserved for the test harness"},
		{"reserved metadata root", "files: {.hoolicy: content}", "reserved for the test harness"},
		{"reserved project directory", "files: {hoolicy.yaml/subdir: content}", "reserved for the test harness"},
		{"reserved case insensitive project", "files: {HOOLICY.YAML: content}", "reserved for the test harness"},
		{"reserved git root", "files: {.git: content}", "reserved for the test harness"},
		{"reserved git metadata", "files: {.git/config: content}", "reserved for the test harness"},
		{"document parent path", "documents: {../outside.yaml: [content]}", "fixture path escapes root"},
		{"overlapping maps", "files: {same.yaml: content}\n    documents: {same.yaml: [content]}", "present in both files and documents"},
		{"file directory collision", "files: {a: content, a/b.txt: content}", "has file ancestor"},
		{"document directory collision", "documents: {a: [content], a/b.txt: [content]}", "has file ancestor"},
		{"cross map directory collision", "files: {a: content}\n    documents: {a/b.txt: [content]}", "has file ancestor"},
		{"case aliased directory collision", "files: {a: content, A/b.txt: content}", "has file ancestor"},
		{"case aliased cross map directory collision", "files: {a: content}\n    documents: {A/b.txt: [content]}", "has file ancestor"},
		{"case aliased files", "files: {A.txt: content, a.txt: content}", "differ only by case"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writePolicyTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: demo
release: 1.0.0
description: Test harness validation.
rules:
  - id: demo.readme
    title: README exists
    description: Requires documentation.
    rationale: Contributors need context.
    remediation: Add the README documentation.
    severity: warning
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`)
			writePolicyTestFile(t, filepath.Join(root, "tests", "cases.yaml"), `version: 1
cases:
  - {name: present, rule: demo.readme, outcome: pass, files: {README.md: ok}}
  - {name: absent, rule: demo.readme, outcome: fail, files: {}}
  - name: invalid harness input
    rule: demo.readme
    outcome: error
    `+test.fixture+"\n")
			result := Run(context.Background(), root, registry)
			if result.Passed != 2 || len(result.Errors) != 1 || !strings.Contains(result.Errors[0], test.message) {
				t.Fatalf("invalid harness fixture passed as an expected evaluation error: %#v", result)
			}
			if _, err := BuildSnapshot(context.Background(), root, registry); err == nil || !strings.Contains(err.Error(), test.message) {
				t.Fatalf("invalid harness fixture entered a behavior snapshot: %v", err)
			}
		})
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

func TestExpectedFindingsDoNotDependOnExpectationOrder(t *testing.T) {
	t.Parallel()
	rule := sdk.Rule{ID: "demo.rule"}
	report := &engine.Report{FailOn: sdk.SeverityError, Findings: []sdk.Finding{
		{RuleID: rule.ID, Severity: sdk.SeverityError, Key: "specific"},
		{RuleID: rule.ID, Severity: sdk.SeverityError, Key: "other"},
	}}
	for _, expected := range [][]ExpectedFinding{
		{{}, {Key: "specific"}},
		{{Key: "specific"}, {}},
	} {
		if err := assertFindings(rule, Case{Outcome: "fail", Expect: expected}, report); err != nil {
			t.Fatalf("valid distinct expectations rejected: %v", err)
		}
	}
	if err := assertFindings(rule, Case{Outcome: "fail", Expect: []ExpectedFinding{{Key: "specific"}, {Key: "specific"}}}, report); err == nil {
		t.Fatal("one finding matched two expectations")
	}
}

// Fixture projects are written as YAML, which omits instantiation-only
// fields. Pack CEL fixtures must still see their checked pack parameters.
func TestFixturesEvaluatePackParametersInCEL(t *testing.T) {
	root := t.TempDir()
	writePolicyTestFile(t, filepath.Join(root, "pack.yaml"), `version: 1
name: probe
release: 0.1.0
description: Probe pack parameters in fixtures.
maturity: experimental
owner: openhoo/hoolicy-maintainers
compatibility: {config: '>=1 <2', hoolicy: '>=0.0.0 <2.0.0'}
parameters:
  minimum: {type: number, default: 2, description: Minimum.}
rules:
  - id: probe.minimum
    title: Minimum
    description: Reads pack parameters.
    rationale: Fixtures must exercise pack parameters.
    remediation: Raise the value.
    severity: error
    kind: structured.cel
    files: [a.json]
    spec:
      format: json
      expression: documents.all(d, d.data.value >= pack.minimum)
      message: Value below pack minimum
`)
	writePolicyTestFile(t, filepath.Join(root, "tests", "cases.yaml"), `version: 1
cases:
  - name: value at minimum passes
    rule: probe.minimum
    outcome: pass
    files: {a.json: '{"value": 2}'}
  - name: value below minimum fails
    rule: probe.minimum
    outcome: fail
    files: {a.json: '{"value": 1}'}
    expect: [{path: '', messageContains: minimum, waived: false}]
`)
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	if result := Run(context.Background(), root, registry); len(result.Errors) > 0 || result.Passed != 2 {
		t.Fatalf("pack parameters unavailable in fixtures: %#v", result)
	}
}
