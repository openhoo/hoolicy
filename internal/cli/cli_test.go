package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
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

func TestCommandsRejectUnexpectedArguments(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "hoolicy.yaml")
	writeCLIFile(t, path, "version: 1\nproject: demo\nrules: []\n")
	tests := [][]string{
		{"version", "extra"},
		{"init", "extra"},
		{"validate", "--config", path, "extra"},
		{"check", "--config", path, "extra"},
		{"list", "--config", path, "extra"},
	}
	for _, args := range tests {
		args := args
		t.Run(args[0], func(t *testing.T) {
			app, _, stderr := testApplication(t)
			if code := app.run(context.Background(), args); code != 2 || !strings.Contains(stderr.String(), "does not accept positional arguments") {
				t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
			}
		})
	}
}

func TestCommandHelpExitsSuccessfully(t *testing.T) {
	t.Parallel()
	commands := [][]string{
		{"version", "-h"}, {"init", "-h"}, {"validate", "-h"}, {"check", "-h"},
		{"fix", "-h"}, {"list", "-h"}, {"explain", "-h"}, {"test", "-h"},
		{"pack", "-h"}, {"pack", "add", "-h"}, {"pack", "update", "-h"}, {"pack", "verify", "-h"},
	}
	for _, args := range commands {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			app, _, stderr := testApplication(t)
			if code := app.run(context.Background(), args); code != 0 {
				t.Fatalf("args=%v code=%d stderr=%q", args, code, stderr.String())
			}
		})
	}
}

func TestPackAddDoesNotSaveInvalidLocalPack(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "hoolicy.yaml")
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	writeCLIFile(t, filepath.Join(root, "packs", "broken", "pack.yaml"), `version: 1
name: broken
release: 1.0.0
description: Broken pack.
rules:
  - id: broken.files
    title: Broken files
    description: Contains an invalid count range.
    rationale: Invalid policy must not be activated.
    remediation: Correct the range.
    severity: error
    kind: files
    files: ['*.txt']
    spec:
      mode: count
      minimum: 2
      maximum: 1
`)
	app, _, stderr := testApplication(t)
	args := []string{"pack", "add", "--config", configPath, "--path", "packs/broken", "broken"}
	if code := app.run(context.Background(), args); code != 2 || !strings.Contains(stderr.String(), "added pack is invalid") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	project, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(project), "broken") {
		t.Fatalf("invalid pack was saved:\n%s", project)
	}
}

func TestPackUpdatePrunesLockAfterLastRemotePackWasRemoved(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	lockPath := filepath.Join(root, config.DefaultLockfile)
	if err := config.SaveLock(lockPath, config.Lock{Version: 1, Packs: []config.LockedPack{{
		Name: "stale", Git: "https://example.com/policy.git", Ref: "v1.0.0", Commit: strings.Repeat("a", 40),
		Digest: "sha256:" + strings.Repeat("b", 64), Vendor: ".hoolicy/vendor/stale",
	}}}); err != nil {
		t.Fatal(err)
	}
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"pack", "update", "--config", configPath}); code != 0 || !strings.Contains(stdout.String(), "Pruned stale") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lock, err := config.LoadLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Packs) != 0 {
		t.Fatalf("stale lock entries remain: %#v", lock.Packs)
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

func TestInitPreservesExistingWaiverFile(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	waiverPath := filepath.Join(root, ".hoolicy", "waivers.yaml")
	writeCLIFile(t, waiverPath, "keep me\n")
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo"}); code != 2 || !strings.Contains(stderr.String(), "already exists") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(waiverPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep me\n" {
		t.Fatalf("existing waiver file changed: %q", data)
	}
	if _, err := os.Stat(filepath.Join(root, "hoolicy.yaml")); !os.IsNotExist(err) {
		t.Fatalf("configuration should not be created, got %v", err)
	}
}

func TestInitRejectsSymlinkedWaiverDirectory(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, ".hoolicy")); err != nil {
		t.Fatal(err)
	}
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo"}); code != 2 || !strings.Contains(stderr.String(), "unsafe waiver path") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	if _, err := os.Stat(filepath.Join(root, "hoolicy.yaml")); !os.IsNotExist(err) {
		t.Fatalf("configuration should not be created, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(outside, "waivers.yaml")); !os.IsNotExist(err) {
		t.Fatalf("outside waiver should not be created, got %v", err)
	}
}

func TestCheckRejectsFormatBeforeTouchingOutput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "hoolicy.yaml")
	outputPath := filepath.Join(root, "report.txt")
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	writeCLIFile(t, outputPath, "keep me\n")
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"check", "--config", configPath, "--format", "invalid", "--output", outputPath}); code != 2 || !strings.Contains(stderr.String(), "unknown report format") {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "keep me\n" {
		t.Fatalf("output was modified: %q", data)
	}
}

func TestCheckOutputDoesNotFollowSymlink(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, "hoolicy.yaml")
	outputPath := filepath.Join(root, "report.json")
	victimPath := filepath.Join(t.TempDir(), "victim.txt")
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	writeCLIFile(t, victimPath, "keep me\n")
	if err := os.Symlink(victimPath, outputPath); err != nil {
		t.Fatal(err)
	}
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"check", "--config", configPath, "--format", "json", "--output", outputPath}); code != 0 {
		t.Fatalf("code=%d stderr=%q", code, stderr.String())
	}
	victim, err := os.ReadFile(victimPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(victim) != "keep me\n" {
		t.Fatalf("symlink target changed: %q", victim)
	}
	info, err := os.Lstat(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		t.Fatal("report path is still a symlink")
	}
	reportData, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(reportData), `"summary"`) {
		t.Fatalf("unexpected report: %s", reportData)
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
