package engine_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/report"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestWaiverLifecycle(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: demo
failOn: error
rules:
  - id: demo.required
    title: Required file
    description: Requires one file.
    rationale: Test needs deterministic finding.
    remediation: Add required.txt.
    severity: error
    kind: files
    files: [required.txt]
    spec:
      mode: require
      message: required.txt is missing
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	writeEngineFile(t, filepath.Join(root, config.DefaultWaivers), "version: 1\nwaivers: []\n")
	first, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.Blocking != 1 || len(first.Findings) != 1 {
		t.Fatalf("unexpected initial report: %#v", first.Summary)
	}
	if first.Waivers == nil {
		t.Fatal("empty waiver list must remain a JSON array")
	}
	waiver := fmt.Sprintf(`version: 1
waivers:
  - id: demo.temporary
    rule: demo.required
    fingerprints: [%s]
    reason: Temporary migration needs a short compatibility window.
    owner: team@example.com
    ticket: https://issues.example.com/DEMO-1
    created: 2026-08-26
    expires: 2026-09-25
`, first.Findings[0].Fingerprint)
	writeEngineFile(t, filepath.Join(root, config.DefaultWaivers), waiver)
	waived, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if waived.Summary.Waived != 1 || waived.Summary.Blocking != 0 || !waived.Findings[0].Waived {
		t.Fatalf("unexpected waived report: %#v %#v", waived.Summary, waived.Findings)
	}
	if err := os.WriteFile(filepath.Join(root, "required.txt"), []byte("done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Summary.Blocking != 1 || len(stale.Findings) != 1 || !strings.Contains(stale.Findings[0].Message, "Stale waiver") {
		t.Fatalf("unexpected stale report: %#v %#v", stale.Summary, stale.Findings)
	}
}

func TestProjectDigestRejectsSymlinkedPolicyInput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, "version: 1\nproject: demo\nrules: []\n")
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	victim := filepath.Join(t.TempDir(), "secret")
	writeEngineFile(t, victim, "do not read\n")
	if err := os.Symlink(victim, filepath.Join(root, config.DefaultLockfile)); err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	checker := engine.New(registry)
	if _, err := checker.Check(context.Background(), project, engine.Options{ToolVersion: "test"}); err == nil || !strings.Contains(err.Error(), "symbolic links are forbidden") {
		t.Fatalf("expected symlinked digest input rejection, got %v", err)
	}
}

func TestUnsafeWaiverParentProducesFindingWithoutReadingOutsideRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, "version: 1\nproject: demo\nrules: []\n")
	outside := t.TempDir()
	if err := os.Mkdir(filepath.Join(outside, "waivers.yaml"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, ".hoolicy")); err != nil {
		t.Fatal(err)
	}
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	report, err := engine.New(sdk.NewRegistry()).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].RuleID != "hoolicy.waivers" || !strings.Contains(report.Findings[0].Message, "unsafe") {
		t.Fatalf("unexpected unsafe-waiver result: %#v", report.Findings)
	}
}

func TestBaselineRatchetsOnlyExactReviewedFinding(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: demo
failOn: error
rules:
  - id: demo.required
    title: Required file
    description: Requires one file.
    rationale: Test needs deterministic finding.
    remediation: Add required.txt.
    severity: error
    kind: files
    files: [required.txt]
    spec:
      mode: require
      message: required.txt is missing
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	first, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	finding := first.Findings[0]
	baseline := config.BaselineFile{
		Version: 1, Project: "demo", CreatedAt: now, ToolVersion: "test", PolicyDigest: first.PolicyDigest,
		Entries: []config.BaselineEntry{{Fingerprint: finding.Fingerprint, RuleID: finding.RuleID, Severity: finding.Severity, PolicyDigest: finding.PolicyDigest, FindingDigest: finding.FindingDigest, CreatedAt: now}},
	}
	if err := config.SaveBaseline(filepath.Join(root, config.DefaultBaseline), baseline); err != nil {
		t.Fatal(err)
	}
	existing, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if existing.Summary.Existing != 1 || existing.Summary.New != 0 || existing.Summary.Blocking != 0 || existing.Findings[0].State != sdk.FindingExisting {
		t.Fatalf("exact baseline did not ratchet finding: %#v %#v", existing.Summary, existing.Findings)
	}
	baseline.Entries[0].Severity = sdk.SeverityWarning
	if err := config.SaveBaseline(filepath.Join(root, config.DefaultBaseline), baseline); err != nil {
		t.Fatal(err)
	}
	changed, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if changed.Summary.New != 1 || changed.Summary.Stale != 1 || changed.Summary.Blocking != 1 || changed.Findings[0].State != sdk.FindingNew {
		t.Fatalf("altered severity weakened baseline: %#v %#v %#v", changed.Summary, changed.Findings, changed.Changes)
	}
	if err := os.WriteFile(filepath.Join(root, "required.txt"), []byte("done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baseline.Entries[0].Severity = sdk.SeverityError
	if err := config.SaveBaseline(filepath.Join(root, config.DefaultBaseline), baseline); err != nil {
		t.Fatal(err)
	}
	fixed, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if fixed.Summary.Fixed != 1 || fixed.Summary.Blocking != 0 || len(fixed.Findings) != 0 {
		t.Fatalf("fixed baseline entry not detected: %#v %#v", fixed.Summary, fixed.Changes)
	}
}

func TestGitComparisonEvaluatesCrossFileRulesOnBothCompleteSnapshots(t *testing.T) {
	root := t.TempDir()
	engineGit(t, root, "init", "-b", "main")
	engineGit(t, root, "config", "user.name", "Hoolicy Test")
	engineGit(t, root, "config", "user.email", "hoolicy@example.com")
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: demo
failOn: error
rules:
  - id: demo.consistency
    title: Versions match
    description: Keeps target manifest aligned.
    rationale: Cross-file drift breaks delivery.
    remediation: Synchronize target version.
    severity: error
    kind: manifest.consistency
    spec:
      authoritative: {path: source.json, pointer: /version}
      targets:
        - {path: target.json, pointer: /version}
      message: Versions must match
`)
	writeEngineFile(t, filepath.Join(root, "source.json"), `{"version":1}`)
	writeEngineFile(t, filepath.Join(root, "target.json"), `{"version":1}`)
	engineGit(t, root, "add", ".")
	engineGit(t, root, "commit", "-m", "test: base policy state")
	base := engineGit(t, root, "rev-parse", "HEAD")
	writeEngineFile(t, filepath.Join(root, "source.json"), `{"version":2}`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	result, err := engine.New(registry).Check(context.Background(), project, engine.Options{Now: time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC), ToolVersion: "test", BaseSHA: base})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].Location.Path != "target.json" || result.Findings[0].State != sdk.FindingNew || result.Summary.Blocking != 1 || result.Comparison == nil || result.Comparison.BaseCommit != base {
		t.Fatalf("cross-file regression not detected: %#v", result)
	}
}

func TestWorkspaceScopesRouteOwnershipAndRejectOverlapOrUnownedPaths(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, filepath.Join(root, "services", "api", "bad.tmp"), "bad\n")
	writeEngineFile(t, filepath.Join(root, "services", "web", "ok.txt"), "ok\n")
	writeEngineFile(t, projectPath, `version: 1
project: demo
workspaces:
  - name: api
    paths: [services/api/**]
    owner: '@api-team'
  - name: web
    paths: [services/web/**]
    owner: '@web-team'
rules:
  - id: demo.temporary
    title: No temporary files
    description: Temporary files do not belong in source.
    rationale: Generated state causes nondeterministic builds.
    remediation: Remove the temporary file.
    severity: error
    kind: files
    files: ['**/*.tmp']
    spec: {mode: forbid, message: Temporary file forbidden}
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	report, err := checker.Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Workspace != "api" || report.Findings[0].Owner != "@api-team" || len(report.Metrics.Rules) != 1 {
		t.Fatalf("unexpected scoped report: %#v", report)
	}
	project.Workspaces[1].Paths = []string{"services/**"}
	if _, err := checker.Validate(project); err == nil || !strings.Contains(err.Error(), "scope overlap") {
		t.Fatalf("overlap accepted: %v", err)
	}
	project.Workspaces[1].Paths = []string{"services/web/**"}
	writeEngineFile(t, filepath.Join(root, "UNOWNED.md"), "unowned\n")
	if _, err := checker.Validate(project); err == nil || !strings.Contains(err.Error(), "unowned workspace path") {
		t.Fatalf("unowned path accepted: %v", err)
	}
}

func TestWorkspaceDependencyExpandsPackRuleInputs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, filepath.Join(root, "shared", "source.json"), `{"version":2}`)
	writeEngineFile(t, filepath.Join(root, "services", "api", "target.json"), `{"version":1}`)
	writeEngineFile(t, filepath.Join(root, ".hoolicy", "packs", "demo", "pack.yaml"), `version: 1
name: demo
release: 0.1.0
description: Cross-workspace invariant.
compatibility: {config: '>=1 <2', hoolicy: '>=0.0.0 <1.0.0'}
rules:
  - id: demo.version
    title: Versions match
    description: Shared and service versions match.
    rationale: Drift breaks deployment.
    remediation: Synchronize target version.
    severity: error
    kind: manifest.consistency
    dependencies: [shared/source.json, services/api/target.json]
    spec:
      authoritative: {path: shared/source.json, pointer: /version}
      targets: [{path: services/api/target.json, pointer: /version}]
`)
	writeEngineFile(t, projectPath, `version: 1
project: demo
packs:
  - name: demo
    path: .hoolicy/packs/demo
workspaces:
  - name: api
    paths: [services/api/**]
    owner: '@api-team'
    packs: [demo]
    dependsOn: [shared]
  - name: shared
    paths: [shared/**]
    owner: '@platform-team'
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	report, err := engine.NewWithVersion(registry, "0.6.0").Check(context.Background(), project, engine.Options{ToolVersion: "0.6.0"})
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) != 1 || report.Findings[0].Workspace != "api" || report.Findings[0].Location.Path != "services/api/target.json" {
		t.Fatalf("dependency input not evaluated: %#v", report.Findings)
	}
}

func TestParsedInputCachePreservesCleanRunParityAndReportsHits(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, filepath.Join(root, "input.json"), `{"enabled":true}`)
	writeEngineFile(t, projectPath, `version: 1
project: demo
rules:
  - id: demo.structured
    title: Enabled
    description: Requires enabled input.
    rationale: Disabled input breaks delivery.
    remediation: Set enabled to true.
    severity: error
    kind: structured.cel
    files: [input.json]
    dependencies: [input.json]
    spec: {format: json, expression: 'documents.all(d, d.data.enabled == true)', message: Input disabled}
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	now := time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)
	clean, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	incremental, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(clean.Findings) != fmt.Sprint(incremental.Findings) || incremental.Metrics.InputCacheHits < 1 || incremental.Metrics.ParseCacheHits < 1 || len(incremental.Metrics.Rules) != 1 || incremental.Metrics.Rules[0].CELCost == 0 {
		t.Fatalf("cache parity or hit missing: clean=%#v cached=%#v", clean, incremental)
	}
}

func TestResourceBudgetsFailClosed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, filepath.Join(root, "large.json"), `{"value":"too large"}`)
	writeEngineFile(t, projectPath, `version: 1
project: demo
budgets:
  maximumFiles: 10
  maximumDocumentBytes: 8
  maximumFindings: 1
  maximumRuleDuration: 1s
  maximumTotalDuration: 2s
rules: []
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := engine.New(sdk.NewRegistry()).Check(context.Background(), project, engine.Options{ToolVersion: "test"}); err == nil || !strings.Contains(err.Error(), "resource budget exceeded") {
		t.Fatalf("oversized input accepted: %v", err)
	}
}

type blockingRule struct{ release <-chan struct{} }

func (blockingRule) Validate(sdk.Rule) error { return nil }
func (rule blockingRule) Evaluate(context.Context, sdk.EvalContext, sdk.Rule) ([]sdk.Finding, error) {
	<-rule.release
	return nil, nil
}

func TestRuleTimeoutIsEnforcedWhenRuleIgnoresContext(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: timeout
budgets:
  maximumFiles: 10
  maximumDocumentBytes: 1024
  maximumFindings: 10
  maximumRuleDuration: 20ms
  maximumTotalDuration: 1s
rules:
  - id: timeout.blocking
    title: Blocking rule
    description: Simulates an uncooperative compile-time extension.
    rationale: Engine deadlines must remain authoritative.
    remediation: Make the extension honor context cancellation.
    severity: error
    kind: test.blocking
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	release := make(chan struct{})
	registry := sdk.NewRegistry()
	if err := registry.Register("test.blocking", blockingRule{release: release}); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	_, err = engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	close(release)
	if err == nil || !strings.Contains(err.Error(), "exceeded execution budget") || time.Since(started) > 500*time.Millisecond {
		t.Fatalf("hard rule timeout failed after %s: %v", time.Since(started), err)
	}
}

func TestCheckPreservesCallerCancellation(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, "version: 1\nproject: canceled\nrules: []\n")
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.New(sdk.NewRegistry()).Check(ctx, project, engine.Options{ToolVersion: "test"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("caller cancellation was hidden: %v", err)
	}
}

func TestCrossPlatformGoldenReportAndPolicyDigest(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: golden
failOn: error
rules:
  - id: golden.readme
    title: README exists
    description: Requires stable repository documentation.
    rationale: Golden reports need one deterministic finding.
    remediation: Add README.md.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	git := sdk.GitContext{Branch: "main", Commit: strings.Repeat("a", 40), CommitSubjects: []sdk.Commit{{SHA: strings.Repeat("a", 40), Subject: "test: golden"}}, Properties: map[string]any{}}
	result, err := engine.New(registry).Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "1.0.0", GitContext: &git})
	if err != nil {
		t.Fatal(err)
	}
	result.Metrics.DurationMilliseconds = 0
	for index := range result.Metrics.Rules {
		result.Metrics.Rules[index].DurationMilliseconds = 0
	}
	var encoded bytes.Buffer
	if err := report.Write(&encoded, "json", result, false); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(encoded.Bytes())
	reportDigest := hex.EncodeToString(sum[:])
	if reportDigest != "4172e93cda291cdf796791cada3ad34c01ab762ba5c6fbd10c4cd5d41fe636ca" || result.PolicyDigest != "sha256:e9b7bcfab1f259a31f555fd25e986f1cad83d37d76e1c853b98b94fdfb85c4eb" {
		t.Fatalf("golden changed: report=%s policy=%s\n%s", reportDigest, result.PolicyDigest, encoded.String())
	}
}

func engineGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}

func BenchmarkEngineCheck(b *testing.B) {
	benchmarkEngineCheck(b, 500)
}

func BenchmarkEngineSmallRepository(b *testing.B) {
	benchmarkEngineCheck(b, 20)
}

func BenchmarkEngineLargeMonorepo(b *testing.B) {
	benchmarkEngineCheck(b, 5_000)
}

func benchmarkEngineCheck(b *testing.B, files int) {
	root := b.TempDir()
	for index := range files {
		writeEngineFile(b, filepath.Join(root, "services", fmt.Sprintf("service-%04d.json", index)), fmt.Sprintf("{\"name\":\"service-%04d\",\"enabled\":true}\n", index))
	}
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(b, projectPath, "version: 1\nproject: benchmark\nfailOn: error\nrules: []\n")
	project, err := config.LoadProject(projectPath)
	if err != nil {
		b.Fatal(err)
	}
	project.Rules = []sdk.Rule{
		benchmarkRule("benchmark.files", "files", []string{"services/**/*.json"}, map[string]any{"mode": "require", "message": "services required"}),
		benchmarkRule("benchmark.text", "text", []string{"services/**/*.json"}, map[string]any{"require": []any{"enabled"}, "message": "enabled required"}),
		benchmarkRule("benchmark.cel", "structured.cel", []string{"services/**/*.json"}, map[string]any{
			"format": "json", "expression": "documents.all(d, d.data.enabled == true)", "message": "services must be enabled",
		}),
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		b.Fatal(err)
	}
	checker := engine.New(registry)
	options := engine.Options{Now: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC), ToolVersion: "benchmark"}
	if _, err := checker.Check(context.Background(), project, options); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := checker.Check(context.Background(), project, options); err != nil {
			b.Fatal(err)
		}
	}
}

func TestGitComparisonReportsDeletedDirectReadInputAsNew(t *testing.T) {
	root := t.TempDir()
	engineGit(t, root, "init", "-b", "main")
	engineGit(t, root, "config", "user.name", "Hoolicy Test")
	engineGit(t, root, "config", "user.email", "hoolicy@example.com")
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(t, projectPath, `version: 1
project: demo
failOn: error
rules:
  - id: demo.direct-read
    title: Required historical input
    description: Reads one required input directly.
    rationale: Deleted inputs must be reported.
    remediation: Restore the required input.
    severity: error
    kind: test.direct-read
    spec: {}
`)
	writeEngineFile(t, filepath.Join(root, "required.txt"), "committed\n")
	engineGit(t, root, "add", ".")
	engineGit(t, root, "commit", "-m", "test: direct read base")
	base := engineGit(t, root, "rev-parse", "HEAD")
	if err := os.Remove(filepath.Join(root, "required.txt")); err != nil {
		t.Fatal(err)
	}
	project, err := config.LoadProject(projectPath)
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := registry.Register("test.direct-read", directReadKind{}); err != nil {
		t.Fatal(err)
	}
	result, err := engine.New(registry).Check(context.Background(), project, engine.Options{ToolVersion: "test", BaseSHA: base})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Findings) != 1 || result.Findings[0].State != sdk.FindingNew || result.Summary.Blocking != 1 {
		t.Fatalf("deleted direct-read input was not blocking new: %#v", result)
	}
}

type directReadKind struct{}

func (directReadKind) Validate(sdk.Rule) error { return nil }

func (directReadKind) Evaluate(_ context.Context, input sdk.EvalContext, rule sdk.Rule) ([]sdk.Finding, error) {
	if _, err := input.Repository.Read("required.txt"); err == nil {
		return nil, nil
	}
	return []sdk.Finding{{Message: "required input is missing", Location: sdk.Location{Path: "required.txt"}, Key: "required"}}, nil
}

func BenchmarkEngineAdversarialLimit(b *testing.B) {
	root := b.TempDir()
	writeEngineFile(b, filepath.Join(root, "oversized.json"), strings.Repeat("x", 64<<10))
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeEngineFile(b, projectPath, `version: 1
project: adversarial
budgets:
  maximumFiles: 10
  maximumDocumentBytes: 1024
  maximumFindings: 10
  maximumRuleDuration: 1s
  maximumTotalDuration: 2s
rules: []
`)
	project, err := config.LoadProject(projectPath)
	if err != nil {
		b.Fatal(err)
	}
	checker := engine.New(sdk.NewRegistry())
	options := engine.Options{Now: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC), ToolVersion: "benchmark"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := checker.Check(context.Background(), project, options); err == nil || !strings.Contains(err.Error(), "resource budget exceeded") {
			b.Fatalf("adversarial input did not fail closed: %v", err)
		}
	}
}

func benchmarkRule(id, kind string, files []string, spec map[string]any) sdk.Rule {
	return sdk.Rule{
		ID: id, Title: "Benchmark rule", Description: "Exercises representative repository policy work.",
		Rationale: "Performance must remain predictable on large repositories.", Remediation: "Correct benchmark fixture.",
		Severity: sdk.SeverityError, Kind: kind, Files: files, Spec: spec,
	}
}

func writeEngineFile(t testing.TB, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
