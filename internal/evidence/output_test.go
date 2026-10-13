package evidence_test

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/evidence"
)

func TestReportOutputProtectsConfiguredInputsAndPackRoots(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "hoolicy.yaml")
	writeEvidenceFile(t, configPath, []byte(`version: 1
project: output
waivers: policy/waivers.yaml
baseline: policy/baseline.json
trust: policy/trust.yaml
evidence: policy/evidence.yaml
packs:
  - {name: local, path: policy/pack}
  - {name: vendor, git: "https://example.invalid/policy.git", ref: main}
rules: []
`))
	digest := "sha256:" + strings.Repeat("a", 64)
	writeEvidenceFile(t, filepath.Join(root, "policy/evidence.yaml"), []byte("version: 1\nexternal:\n  - id: scan\n    type: sarif\n    path: reports/scan.json\n    sha256: "+digest+"\n    subjectDigest: "+digest+"\n"))
	project, err := config.LoadProject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, relative := range []string{"hoolicy.yaml", "hoolicy.lock", "policy/waivers.yaml", "policy/baseline.json", "policy/trust.yaml", "policy/evidence.yaml", "reports/scan.json", "policy/pack/new/file.json", ".hoolicy/vendor/vendor/new/file.json", ".gitignore", ".GITIGNORE"} {
		t.Run(relative, func(t *testing.T) {
			output := filepath.Join(root, filepath.FromSlash(relative))
			if _, err := evidence.ReportOutputPath(project, output); err == nil {
				t.Fatal("policy output accepted")
			}
			if _, err := os.Stat(output); relative != "hoolicy.yaml" && relative != "policy/evidence.yaml" && !os.IsNotExist(err) {
				t.Fatalf("preflight wrote output: %v", err)
			}
		})
	}
	output := filepath.Join(root, "new", "report.json")
	if _, err := evidence.ReportOutputPath(project, output); err != nil {
		t.Fatalf("ordinary in-source report rejected: %v", err)
	}
	if _, err := os.Stat(filepath.Dir(output)); !os.IsNotExist(err) {
		t.Fatalf("preflight created report parents: %v", err)
	}
	if _, err := evidence.OutputPaths(project, []string{output}); err == nil {
		t.Fatal("evidence unexpectedly allowed inside plain source")
	}
	alias := filepath.Join(root, "report-alias.json")
	if err := os.Symlink(configPath, alias); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.ReportOutputPath(project, alias); err == nil {
		t.Fatal("policy alias output accepted")
	}
}

func TestReportOutputProtectsMissingUnicodePolicyAliases(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "hoolicy.yaml")
	writeEvidenceFile(t, configPath, []byte("version: 1\nproject: alias\nwaivers: policy/waivers-Å.yaml\nrules: []\n"))
	project, err := config.LoadProject(configPath)
	if err != nil {
		t.Fatal(err)
	}
	output := filepath.Join(root, "policy", "waivers-A\u030a.yaml")
	_, err = evidence.ReportOutputPath(project, output)
	insensitive := runtime.GOOS == "darwin" || runtime.GOOS == "windows"
	if (err != nil) != insensitive {
		t.Fatalf("missing normalization alias: insensitive=%v err=%v", insensitive, err)
	}
}
