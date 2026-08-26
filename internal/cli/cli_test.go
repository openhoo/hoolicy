package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestValidateListCheckAndThresholdOverride(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "hoolicy.yaml")
	writeCLIFile(t, path, `version: 1
project: demo
failOn: error
rules:
  - id: demo.readme
    title: README exists
    description: Requires repository documentation.
    rationale: Contributors need an entry point.
    remediation: Add README.md.
    severity: warning
    kind: files
    files: [README.md]
    spec:
      mode: require
      message: README missing
`)

	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"validate", "--config", path}); code != 0 || !strings.Contains(stdout.String(), "1 active rules") {
		t.Fatalf("validate code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"list", "--config", path}); code != 0 || !strings.Contains(stdout.String(), "demo.readme") {
		t.Fatalf("list code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"check", "--config", path, "--format", "json"}); code != 0 || !strings.Contains(stdout.String(), `"blocking": 0`) {
		t.Fatalf("default check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"check", "--config", path, "--fail-on", "info"}); code != 1 {
		t.Fatalf("strict check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestFailOnCannotWeakenProjectPolicy(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "hoolicy.yaml")
	writeCLIFile(t, path, "version: 1\nproject: strict\nfailOn: warning\nrules: []\n")
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"check", "--config", path, "--fail-on", "error"}); code != 2 || !strings.Contains(stderr.String(), "may not weaken") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
}

func TestInitCreatesUsefulStarter(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo", "--profile", "strict"}); code != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	data, err := os.ReadFile(filepath.Join(root, "hoolicy.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "repository.readme") || !strings.Contains(string(data), "requireDigest: true") {
		t.Fatalf("unexpected starter config:\n%s", data)
	}
}

func testApplication(t *testing.T) (application, *bytes.Buffer, *bytes.Buffer) {
	t.Helper()
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	stdout := &bytes.Buffer{}
	stderr := &bytes.Buffer{}
	return application{
		stdout: stdout, stderr: stderr, info: BuildInfo{Version: "test", Commit: "test", Date: "test"},
		registry: registry, engine: engine.New(registry),
	}, stdout, stderr
}

func writeCLIFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
