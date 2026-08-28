package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/evidence"
	"github.com/openhoo/hoolicy/internal/report"
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
		{"baseline", "-h"}, {"baseline", "create", "-h"}, {"baseline", "prune", "-h"},
		{"doctor", "-h"}, {"report", "-h"}, {"report", "diff", "-h"},
		{"fmt", "-h"}, {"lint", "-h"},
		{"evidence", "-h"}, {"evidence", "verify", "-h"},
		{"waiver", "-h"}, {"waiver", "create", "-h"}, {"inventory", "-h"}, {"serve", "-h"},
		{"migrate", "-h"}, {"migrate", "report", "-h"},
		{"pack", "-h"}, {"pack", "init", "-h"}, {"pack", "add", "-h"}, {"pack", "update", "-h"}, {"pack", "verify", "-h"}, {"pack", "snapshot", "-h"}, {"pack", "compare", "-h"}, {"pack", "catalog", "-h"}, {"pack", "catalog", "publish", "-h"}, {"pack", "catalog", "pull", "-h"}, {"pack", "catalog", "verify", "-h"}, {"pack", "catalog", "resolve", "-h"},
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

func TestSignedCatalogVerifyResolveAndTamperDetection(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "catalog.json")
	catalog := config.Catalog{
		Version:     config.CurrentVersion,
		Name:        "official",
		GeneratedAt: time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC),
		Packs: []config.CatalogEntry{
			{Name: "security", Release: "1.2.0", OCI: "ghcr.io/openhoo/security:v1.2.0"},
			{Name: "security", Release: "1.10.0", OCI: "ghcr.io/openhoo/security:v1.10.0"},
		},
	}
	data, err := json.MarshalIndent(catalog, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	data = append(data, '\n')
	writeCLIBytes(t, path, data)
	digest := sha256.Sum256(data)
	lock := config.CatalogLock{
		Version:        config.CurrentVersion,
		Source:         "ghcr.io/openhoo/catalog:v1",
		ManifestDigest: "sha256:" + strings.Repeat("a", 64),
		CatalogDigest:  "sha256:" + hex.EncodeToString(digest[:]),
		VerifiedBy:     "official",
	}
	if err := config.SaveCatalogLock(path+".lock", lock); err != nil {
		t.Fatal(err)
	}
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"pack", "catalog", "verify", path}); code != 0 || !strings.Contains(stdout.String(), "Verified signed catalog official") {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "catalog", "resolve", path, "security"}); code != 0 || !strings.Contains(stdout.String(), "security 1.10.0 ghcr.io/openhoo/security:v1.10.0") {
		t.Fatalf("resolve code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	writeCLIBytes(t, path, append(data, ' '))
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "catalog", "verify", path}); code != 2 || !strings.Contains(stderr.String(), "catalog digest mismatch") {
		t.Fatalf("tamper code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestEvidenceCreateAndVerifyWithoutCIUI(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	for _, args := range [][]string{{"init", "-q"}, {"config", "user.name", "Hoolicy Tests"}, {"config", "user.email", "tests@hoolicy.invalid"}, {"add", "hoolicy.yaml"}, {"commit", "-q", "-m", "test: evidence subject"}} {
		command := exec.Command("git", append([]string{"-C", root}, args...)...)
		if output, err := command.CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v: %s", args, err, output)
		}
	}
	output := filepath.Join(t.TempDir(), "evidence.json")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"evidence", "--config", configPath, "--output", output}); code != 0 || !strings.Contains(stdout.String(), "Wrote verifiable evidence") {
		t.Fatalf("create code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"evidence", "verify", "--config", configPath, output}); code != 0 || !strings.Contains(stdout.String(), "Verified evidence bundle") {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestWaiverCreateIsPreviewFirstAndFindingBound(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, `version: 1
project: demo
requireWaiverApprover: true
rules:
  - id: demo.readme
    title: README
    description: Requires repository documentation.
    rationale: Contributors need reviewed context.
    remediation: Add a reviewed README file.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require, message: README missing}
`)
	app, stdout, stderr := testApplication(t)
	project, err := config.LoadProject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := app.engine.Check(context.Background(), project, engine.Options{ToolVersion: "test"})
	if err != nil || len(decision.Findings) != 1 {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	fingerprint := decision.Findings[0].Fingerprint
	base := []string{"waiver", "create", "--config", configPath, "--fingerprint", fingerprint, "--owner", "team@example.com", "--approver", "reviewer@example.com", "--ticket", "https://issues.example.com/SEC-1", "--reason", "Temporary exception while reviewed remediation is delivered.", "--expires", time.Now().UTC().AddDate(0, 0, 10).Format("2006-01-02")}
	if code := app.run(context.Background(), base); code != 0 || !strings.Contains(stdout.String(), "No files changed") {
		t.Fatalf("preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	waiverPath := filepath.Join(root, config.DefaultWaivers)
	if _, err := os.Stat(waiverPath); !os.IsNotExist(err) {
		t.Fatalf("preview wrote waiver: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), append(base, "--apply")); code != 0 || !strings.Contains(stdout.String(), "Applied waiver") {
		t.Fatalf("apply code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	loaded, err := config.LoadWaivers(waiverPath)
	if err != nil || len(loaded.Waivers) != 1 || loaded.Waivers[0].Fingerprints[0] != fingerprint || loaded.Waivers[0].Approver == "" {
		t.Fatalf("waivers=%#v err=%v", loaded, err)
	}
}

func TestInventoryAndReadOnlyServiceUseSameEngineContract(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, "version: 1\nproject: demo\nrules: []\n")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"inventory", "--config", configPath}); code != 0 {
		t.Fatalf("inventory code=%d stderr=%q", code, stderr.String())
	}
	var inventory policyInventory
	if err := json.Unmarshal(stdout.Bytes(), &inventory); err != nil || inventory.Project != "demo" || len(inventory.Scopes) != 1 {
		t.Fatalf("inventory=%#v err=%v", inventory, err)
	}
	if inventory.Waivers == nil {
		t.Fatal("empty inventory waivers must remain a JSON array")
	}
	handler := app.readOnlyHandler(configPath)
	get := httptest.NewRecorder()
	handler.ServeHTTP(get, httptest.NewRequest(http.MethodGet, "/v1/check", nil))
	if get.Code != http.StatusOK {
		t.Fatalf("GET status=%d body=%s", get.Code, get.Body.String())
	}
	var decision engine.Report
	if err := json.Unmarshal(get.Body.Bytes(), &decision); err != nil || decision.PolicyDigest != inventory.PolicyDigest {
		t.Fatalf("decision=%#v err=%v", decision, err)
	}
	post := httptest.NewRecorder()
	handler.ServeHTTP(post, httptest.NewRequest(http.MethodPost, "/v1/check", nil))
	if post.Code != http.StatusMethodNotAllowed {
		t.Fatalf("mutation method accepted: %d", post.Code)
	}
	stderr.Reset()
	if code := app.run(context.Background(), []string{"serve", "--config", configPath, "--listen", "0.0.0.0:8941"}); code != 2 || !strings.Contains(stderr.String(), "loopback") {
		t.Fatalf("non-loopback serve code=%d stderr=%q", code, stderr.String())
	}
	stderr.Reset()
	if code := app.run(context.Background(), []string{"serve", "--config", configPath, "--listen", "localhost:8941"}); code != 2 || !strings.Contains(stderr.String(), "numeric loopback") {
		t.Fatalf("hostname listen code=%d stderr=%q", code, stderr.String())
	}
}

func TestCommandOutputLineRemovesControlsAndCredentials(t *testing.T) {
	t.Parallel()
	output := commandOutputLine([]byte("https://secret@example.com/failure\x1b[31m\n" + strings.Repeat("x", 600)))
	if strings.Contains(output, "secret") || strings.ContainsRune(output, '\x1b') || len([]rune(output)) > 500 {
		t.Fatalf("unsafe command output: %q", output)
	}
}

func TestFailedAttestationSigningPublishesNoFinalFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture uses POSIX shell")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeCLIFile(t, filepath.Join(bin, "cosign"), "#!/bin/sh\nexit 1\n")
	if err := os.Chmod(filepath.Join(bin, "cosign"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin)
	statementPath := filepath.Join(root, "decision.intoto.json")
	bundlePath := filepath.Join(root, "decision.sigstore.json")
	bundle := &evidence.Bundle{Project: "demo", Revision: strings.Repeat("a", 40), PolicyDigest: "sha256:" + strings.Repeat("b", 64), Decision: &engine.Report{}}
	if err := createDecisionAttestation(statementPath, bundlePath, "key", false, bundle, []byte("{}\n")); err == nil {
		t.Fatal("failed Cosign command accepted")
	}
	for _, path := range []string{statementPath, bundlePath} {
		if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("failed signing published %s: %v", path, err)
		}
	}
}

func TestReportMigrationIsPreviewFirst(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "report.json")
	original := `{"reportVersion":1,"configDigest":"sha256:` + strings.Repeat("a", 64) + `","findings":[]}` + "\n"
	writeCLIFile(t, path, original)
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"migrate", "report", path}); code != 0 || !strings.Contains(stdout.String(), "No files changed") {
		t.Fatalf("preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	unchanged, err := os.ReadFile(path)
	if err != nil || string(unchanged) != original {
		t.Fatalf("preview mutated input: %q err=%v", unchanged, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"migrate", "report", "--apply", path}); code != 0 {
		t.Fatalf("apply code=%d stderr=%q", code, stderr.String())
	}
	migrated, err := report.LoadJSON(path)
	if err != nil || migrated.ReportVersion != 2 || migrated.PolicyDigest != migrated.ConfigDigest || migrated.Waivers == nil || migrated.Metrics.Rules == nil {
		t.Fatalf("migrated=%#v err=%v", migrated, err)
	}
}

func TestPackInitLintFormatSnapshotAndMachineExplain(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	packPath := filepath.Join(root, "demo-pack")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"pack", "init", "--name", "demo", packPath}); code != 0 {
		t.Fatalf("init code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := config.LoadPack(packPath); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(packPath, "pack.yaml"), filepath.Join(packPath, "tests", "cases.yaml")} {
		data, err := os.ReadFile(path)
		if err != nil || !strings.Contains(string(data), "yaml-language-server: $schema=") || !strings.Contains(string(data), "/schemas/v1/") {
			t.Fatalf("missing versioned schema directive in %s: %q, %v", path, data, err)
		}
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"lint", packPath}); code != 0 || !strings.Contains(stdout.String(), "0 lint findings") {
		t.Fatalf("lint code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "snapshot", packPath}); code != 1 || !strings.Contains(stdout.String(), "--update") {
		t.Fatalf("snapshot preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if _, err := os.Stat(filepath.Join(packPath, "tests", "snapshot.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("snapshot preview wrote file: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "snapshot", "--update", packPath}); code != 0 {
		t.Fatalf("snapshot update code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "snapshot", packPath}); code != 0 || !strings.Contains(stdout.String(), "matches") {
		t.Fatalf("snapshot verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	casesPath := filepath.Join(packPath, "tests", "cases.yaml")
	writeCLIFile(t, casesPath, "version: 1\ncases:\n- {name: present, rule: demo.required-file, outcome: pass, files: {REQUIRED.md: ok}}\n- {name: absent, rule: demo.required-file, outcome: fail, files: {}}\n")
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"fmt", "--check", casesPath}); code != 1 {
		t.Fatalf("fmt check code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if data, _ := os.ReadFile(casesPath); !strings.Contains(string(data), "- {") {
		t.Fatal("fmt --check modified file")
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"fmt", casesPath}); code != 0 {
		t.Fatalf("fmt code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	projectPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, projectPath, "version: 1\nproject: demo\npacks:\n  - name: demo\n    path: demo-pack\n")
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"explain", "--config", projectPath, "--format", "json", "demo.required-file"}); code != 0 || !strings.Contains(stdout.String(), `"policyDigest"`) {
		t.Fatalf("explain code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestPackScaffoldCompatibilityTracksStableEngineLine(t *testing.T) {
	t.Parallel()
	tests := map[string]string{
		"0.1.3-0.20260827192717-081c2b065b8d": ">=0.1.3-0 <0.1.3 || >=0.2.0 <2.0.0",
		"0.2.0":                               ">=0.2.0 <2.0.0",
		"1.0.0":                               ">=1.0.0 <2.0.0",
	}
	for version, expected := range tests {
		if actual := scaffoldHoolicyCompatibility(version); actual != expected {
			t.Fatalf("%s compatibility = %q, want %q", version, actual, expected)
		}
	}
}

func TestPackPublishCannotBypassFixturesSnapshotOrCompatibilityReport(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture uses POSIX shell")
	}
	root := t.TempDir()
	packPath := filepath.Join(root, "demo")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"pack", "init", "--name", "demo", packPath}); code != 0 {
		t.Fatalf("init code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	publication := []string{"pack", "publish", "--reference", "ghcr.io/openhoo/demo:0.1.0", "--provenance", "sha256:" + strings.Repeat("c", 64), "--keyless", packPath}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), publication); code != 2 || !strings.Contains(stderr.String(), "reviewed behavior snapshot is required") {
		t.Fatalf("missing snapshot code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	casesPath := filepath.Join(packPath, "tests", "cases.yaml")
	caseData, err := os.ReadFile(casesPath)
	if err != nil {
		t.Fatal(err)
	}
	writeCLIBytes(t, casesPath, append(caseData, []byte("unknown: true\n")...))
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), publication); code != 2 || !strings.Contains(stderr.String(), "fixture suite failed") {
		t.Fatalf("broken fixtures code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	writeCLIBytes(t, casesPath, caseData)
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "snapshot", "--update", packPath}); code != 0 {
		t.Fatalf("snapshot code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	orasPath := filepath.Join(bin, "oras")
	writeCLIFile(t, orasPath, `#!/bin/sh
set -eu
test "$1" = push
test -s pack.tar.gz
test -s release-manifest.json
test -s compatibility.json
test -s test-results.json
grep -q '"current": "0.1.0"' compatibility.json
grep -q '"passed": 2' test-results.json
printf '%s\n' sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`)
	cosignPath := filepath.Join(bin, "cosign")
	writeCLIFile(t, cosignPath, `#!/bin/sh
case " $* " in
  *" ghcr.io/openhoo/demo@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd "*) exit 0 ;;
  *) exit 2 ;;
esac
`)
	if err := os.Chmod(orasPath, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(cosignPath, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), publication); code != 0 || !strings.Contains(stdout.String(), "Published and signed") {
		t.Fatalf("publish code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestBaselineCreateCheckAndPruneArePreviewFirst(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, `version: 1
project: demo
failOn: error
rules:
  - id: demo.required
    title: Required file
    description: Requires a repository marker.
    rationale: Tests baseline adoption.
    remediation: Add required.txt.
    severity: error
    kind: files
    files: [required.txt]
    spec: {mode: require, message: required.txt missing}
`)
	app, stdout, stderr := testApplication(t)
	create := []string{"baseline", "create", "--config", configPath}
	if code := app.run(context.Background(), create); code != 0 || !strings.Contains(stdout.String(), "Preview only") {
		t.Fatalf("preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	baselinePath := filepath.Join(root, config.DefaultBaseline)
	if _, err := os.Stat(baselinePath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preview wrote baseline: %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), append(create, "--apply")); code != 0 {
		t.Fatalf("apply code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	baseline, err := config.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Entries) != 1 {
		t.Fatalf("unexpected baseline: %#v", baseline)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"check", "--config", configPath, "--format", "json"}); code != 0 || !strings.Contains(stdout.String(), `"existing": 1`) {
		t.Fatalf("ratchet code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	writeCLIFile(t, filepath.Join(root, "required.txt"), "done\n")
	stdout.Reset()
	stderr.Reset()
	prune := []string{"baseline", "prune", "--config", configPath}
	if code := app.run(context.Background(), prune); code != 0 || !strings.Contains(stdout.String(), "fingerprint no longer reproduces") {
		t.Fatalf("prune preview code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	baseline, err = config.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Entries) != 1 {
		t.Fatal("prune preview modified baseline")
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), append(prune, "--apply")); code != 0 {
		t.Fatalf("prune apply code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	baseline, err = config.LoadBaseline(baselinePath)
	if err != nil {
		t.Fatal(err)
	}
	if len(baseline.Entries) != 0 {
		t.Fatalf("prune left entries: %#v", baseline.Entries)
	}
}

func TestDoctorDiagnosesUnsupportedStructuredInputs(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, `version: 1
project: demo
rules:
  - id: demo.structured
    title: Structured input
    description: Parses matched structured input.
    rationale: Test doctor parser readiness.
    remediation: Use a supported format.
    severity: error
    kind: structured.cel
    files: [input.unsupported]
    spec:
      expression: documents.size() == 1
      message: one document required
`)
	writeCLIFile(t, filepath.Join(root, "input.unsupported"), "value\n")
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"doctor", "--config", configPath}); code != 2 || !strings.Contains(stderr.String(), "unsupported file types") || !strings.Contains(stderr.String(), "unsupported document format") {
		t.Fatalf("doctor code=%d stderr=%q", code, stderr.String())
	}
}

func TestDoctorWarnsAboutIgnoredTargetsAndMissingCIBase(t *testing.T) {
	root := t.TempDir()
	runCLICommand(t, root, "git", "init", "-q", "-b", "main")
	runCLICommand(t, root, "git", "config", "user.name", "Hoolicy Tests")
	runCLICommand(t, root, "git", "config", "user.email", "tests@hoolicy.invalid")
	configPath := filepath.Join(root, config.DefaultFilename)
	writeCLIFile(t, configPath, `version: 1
project: demo
rules:
  - id: demo.required
    title: Required ignored input
    description: Requires one JSON input.
    rationale: Test ignored target diagnosis.
    remediation: Stop ignoring the policy input.
    severity: error
    kind: files
    files: [ignored.json]
    spec: {mode: require, message: ignored.json required}
`)
	writeCLIFile(t, filepath.Join(root, ".gitignore"), "ignored.json\n")
	writeCLIFile(t, filepath.Join(root, "ignored.json"), "{}\n")
	runCLICommand(t, root, "git", "add", config.DefaultFilename, ".gitignore")
	runCLICommand(t, root, "git", "commit", "-qm", "test: doctor")
	t.Setenv("GITHUB_EVENT_NAME", "pull_request")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"doctor", "--config", configPath}); code != 1 || !strings.Contains(stdout.String(), "WARN ci-base-revision missing") || !strings.Contains(stdout.String(), "WARN ignored-target ignored.json") {
		t.Fatalf("doctor code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
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
	if code := app.run(context.Background(), []string{"pack", "update", "--config", configPath}); code != 0 || !strings.Contains(stdout.String(), "Preview only") {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lock, err := config.LoadLock(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Packs) != 1 {
		t.Fatalf("preview modified lock: %#v", lock.Packs)
	}
	stdout.Reset()
	stderr.Reset()
	if code := app.run(context.Background(), []string{"pack", "update", "--config", configPath, "--apply"}); code != 0 || !strings.Contains(stdout.String(), "Pruned stale") {
		t.Fatalf("apply code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lock, err = config.LoadLock(lockPath)
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
	writeCLIBytes(t, path, []byte(body))
}

func writeCLIBytes(t *testing.T, path string, body []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o644); err != nil {
		t.Fatal(err)
	}
}

func runCLICommand(t *testing.T, root, name string, args ...string) {
	t.Helper()
	command := exec.Command(name, args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v: %s", name, args, err, output)
	}
}
