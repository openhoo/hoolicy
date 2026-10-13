package cli

import (
	"context"
	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/report"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCheckOutputPreservesPolicyAndGitMetadata(t *testing.T) {
	for _, command := range []string{"check", "inventory", "migrate report"} {
		for _, scenario := range []string{"configuration", "lock", "policy input parent", "git metadata", "indirect git metadata", "policy alias", "ignore policy", "missing metadata parent"} {
			t.Run(command+"/"+scenario, func(t *testing.T) {
				root := t.TempDir()
				configPath := filepath.Join(root, "hoolicy.yaml")
				writeCLIFile(t, configPath, "version: 1\nproject: report-output\nrules: []\n")
				output := configPath
				switch scenario {
				case "lock":
					output = filepath.Join(root, "hoolicy.lock")
				case "policy input parent":
					output = filepath.Join(root, ".hoolicy")
				case "git metadata", "missing metadata parent":
					runCLICommand(t, root, "git", "init", "-q", "-b", "main")
					output = filepath.Join(root, ".git", "HEAD")
					if scenario == "missing metadata parent" {
						output = filepath.Join(root, ".git", "new", "report.json")
					}
				case "indirect git metadata":
					metadata := filepath.Join(t.TempDir(), "metadata")
					runCLICommand(t, root, "git", "init", "-q", "-b", "main", "--separate-git-dir", metadata)
					output = filepath.Join(metadata, "HEAD")
				case "policy alias":
					alias := filepath.Join(t.TempDir(), "alias")
					if err := os.Symlink(root, alias); err != nil {
						t.Fatal(err)
					}
					output = filepath.Join(alias, "hoolicy.yaml")
				case "ignore policy":
					output = filepath.Join(root, ".gitignore")
					writeCLIFile(t, output, "report.json\n")
				}
				before, beforeErr := os.ReadFile(output)
				app, _, stderr := testApplication(t)
				args := []string{command, "--config", configPath, "--output", output}
				if command == "migrate report" {
					project, err := config.LoadProject(configPath)
					if err != nil {
						t.Fatal(err)
					}
					digest, err := report.LegacyProjectDigest(project, nil)
					if err != nil {
						t.Fatal(err)
					}
					input := filepath.Join(t.TempDir(), "old-report.json")
					original := `{"reportVersion":1,"tool":{"name":"hoolicy","version":"0.1.2"},"project":"report-output","generatedAt":"2026-08-28T12:00:00Z","configDigest":"` + digest + `","git":{"branch":"","commit":"","commits":[],"mergeRequestTitle":"","dirty":false},"failOn":"error","findings":[],"summary":{"rules":0,"errors":0,"warnings":0,"info":0,"waived":0,"blocking":0}}`
					writeCLIFile(t, input, original)
					args = []string{"migrate", "report", "--config", configPath, "--output", output, "--apply", input}
				}
				if code := app.run(context.Background(), args); code != 2 || !strings.Contains(stderr.String(), "report output") {
					t.Fatalf("unsafe output: code=%d stderr=%q", code, stderr.String())
				}
				after, afterErr := os.ReadFile(output)
				if string(before) != string(after) || os.IsNotExist(beforeErr) != os.IsNotExist(afterErr) {
					t.Fatalf("output was changed: before=%q after=%q err=%v", before, after, afterErr)
				}
				if scenario == "missing metadata parent" {
					if _, err := os.Stat(filepath.Dir(output)); !os.IsNotExist(err) {
						t.Fatalf("rejected output created parents: %v", err)
					}
				}
			})
		}
	}
}
