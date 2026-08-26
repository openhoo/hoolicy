package engine

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
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
	checker := New(registry)
	now := time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)
	first, err := checker.Check(context.Background(), project, Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if first.Summary.Blocking != 1 || len(first.Findings) != 1 {
		t.Fatalf("unexpected initial report: %#v", first.Summary)
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
	waived, err := checker.Check(context.Background(), project, Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if waived.Summary.Waived != 1 || waived.Summary.Blocking != 0 || !waived.Findings[0].Waived {
		t.Fatalf("unexpected waived report: %#v %#v", waived.Summary, waived.Findings)
	}
	if err := os.WriteFile(filepath.Join(root, "required.txt"), []byte("done\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	stale, err := checker.Check(context.Background(), project, Options{Now: now, ToolVersion: "test"})
	if err != nil {
		t.Fatal(err)
	}
	if stale.Summary.Blocking != 1 || len(stale.Findings) != 1 || !strings.Contains(stale.Findings[0].Message, "Stale waiver") {
		t.Fatalf("unexpected stale report: %#v %#v", stale.Summary, stale.Findings)
	}
}

func writeEngineFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
