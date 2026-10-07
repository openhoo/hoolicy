package cli

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
)

func TestStarterProfilesPassAndFailOffline(t *testing.T) {
	t.Parallel()
	for _, profile := range starterProfiles {
		t.Run(profile.name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			app, stdout, stderr := testApplication(t)
			if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo", "--profile", profile.name}); code != 0 {
				t.Fatalf("init code=%d stdout=%s stderr=%s", code, stdout, stderr)
			}
			project, err := config.LoadProject(filepath.Join(root, config.DefaultFilename))
			if err != nil {
				t.Fatal(err)
			}
			if len(project.Packs) != 0 {
				t.Fatal("starter policy must not acquire packs")
			}
			for name, content := range map[string]string{
				"README.md": "Repository documentation\n", "LICENSE": "MIT\n", "SECURITY.md": "Private reporting instructions\n",
				"go.mod": "module example.com/demo\n\ngo 1.26\n", "go.sum": "",
				"package.json":      `{"name":"demo","version":"1.0.0","license":"MIT","packageManager":"npm@11.0.0","dependencies":{"example":"1.0.0"}}`,
				"package-lock.json": `{"lockfileVersion":3}`, "CHANGELOG.md": "Release history\n", "RUNBOOK.md": "Recovery instructions\n",
				"Dockerfile": "FROM ghcr.io/example/demo@sha256:" + strings.Repeat("a", 64) + "\n", ".dockerignore": ".env\n.git\n",
			} {
				writeCLIFile(t, filepath.Join(root, name), content)
			}
			decision, err := app.engine.Check(context.Background(), project, engine.Options{Branch: "main"})
			if err != nil || decision.Summary.Blocking != 0 {
				t.Fatalf("positive decision=%#v err=%v", decision, err)
			}
			if profile.name == "empty" {
				return
			}
			negativePath, negativeRule := "README.md", "repository.readme"
			switch profile.name {
			case "go-library", "go-service":
				writeCLIFile(t, filepath.Join(root, "go.mod"), "module example.com/demo\nreplace example.com/dependency => ../unreviewed\n")
				negativePath, negativeRule = "", "go.dependencies"
			case "node-library", "node-service":
				negativePath, negativeRule = "package-lock.json", "node.dependencies"
			case "container-service":
				writeCLIFile(t, filepath.Join(root, "Dockerfile"), "FROM ghcr.io/example/demo:latest\n")
				negativePath, negativeRule = "", "supply-chain.approved-sources"
			}
			if negativePath != "" {
				if err := os.Remove(filepath.Join(root, negativePath)); err != nil {
					t.Fatal(err)
				}
			}
			decision, err = app.engine.Check(context.Background(), project, engine.Options{Branch: "main"})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range decision.Findings {
				found = found || finding.RuleID == negativeRule
			}
			if !found || decision.Summary.Blocking == 0 {
				t.Fatalf("missing negative finding %s: %#v", negativeRule, decision)
			}
		})
	}
}

func TestInitListsProfilesWithoutFilesystemChanges(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "not-created")
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"init", "--list-profiles", "--directory", root}); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	for _, profile := range starterProfiles {
		if !strings.Contains(stdout.String(), profile.name+"\t") {
			t.Errorf("missing profile %s", profile.name)
		}
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("listing created target: %v", err)
	}
}

func TestInitUnknownProfileDoesNotCreateFiles(t *testing.T) {
	t.Parallel()
	root := filepath.Join(t.TempDir(), "not-created")
	app, _, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"init", "--profile", "unknown", "--directory", root}); code != 2 || !strings.Contains(stderr.String(), "--list-profiles") {
		t.Fatalf("code=%d stderr=%s", code, stderr)
	}
	if _, err := os.Lstat(root); !os.IsNotExist(err) {
		t.Fatalf("invalid profile created target: %v", err)
	}
}

func TestStackStarterRulesReportMissingRequiredEvidence(t *testing.T) {
	t.Parallel()
	for _, profile := range []string{"go-library", "go-service", "node-library", "node-service", "container-service"} {
		t.Run(profile, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			app, _, stderr := testApplication(t)
			if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo", "--profile", profile}); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr)
			}
			project, err := config.LoadProject(filepath.Join(root, config.DefaultFilename))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := app.engine.Check(context.Background(), project, engine.Options{Branch: "main"})
			if err != nil {
				t.Fatal(err)
			}
			for _, rule := range stackStarterRules(profile) {
				if rule.Kind != "files" {
					continue
				}
				found := false
				for _, finding := range decision.Findings {
					found = found || finding.RuleID == rule.ID
				}
				if !found {
					t.Errorf("missing required-file finding for %s", rule.ID)
				}
			}
		})
	}
}

func TestNodeStarterMetadataReportsMissingAndWrongTypes(t *testing.T) {
	t.Parallel()
	for _, manifest := range []string{
		`{"name":"demo","version":"1.0.0"}`,
		`{"name":"demo","version":42,"license":"MIT"}`,
		`{"name":"","version":"1.0.0","license":"MIT"}`,
	} {
		t.Run(manifest, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			app, _, stderr := testApplication(t)
			if code := app.run(context.Background(), []string{"init", "--directory", root, "--project", "demo", "--profile", "node-library"}); code != 0 {
				t.Fatalf("code=%d stderr=%s", code, stderr)
			}
			writeCLIFile(t, filepath.Join(root, "package.json"), manifest)
			project, err := config.LoadProject(filepath.Join(root, config.DefaultFilename))
			if err != nil {
				t.Fatal(err)
			}
			decision, err := app.engine.Check(context.Background(), project, engine.Options{Branch: "main"})
			if err != nil {
				t.Fatal(err)
			}
			found := false
			for _, finding := range decision.Findings {
				found = found || finding.RuleID == "node.metadata"
			}
			if !found {
				t.Fatalf("missing metadata finding: %#v", decision)
			}
		})
	}
}
