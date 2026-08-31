package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestSyncReleaseVersion(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "VERSION", "2.3.4\n")
	writeTestFile(t, root, "README.md", strings.Join([]string{
		"github.com/openhoo/hoolicy/cmd/hoolicy@v0.1.1",
		"ghcr.io/openhoo/hoolicy:v0.1.1",
		"ref: v0.1.1",
		"v1.0.0 stays unchanged",
	}, "\n"))
	writeTestFile(t, root, "SECURITY.md", "Security fixes target the latest `v0.1.x` release.\n")
	writeTestFile(t, root, "actions/setup/action.yml", "inputs:\n  version:\n    default: \"0.1.1\"\n")
	writeTestFile(t, root, "actions/check/action.yml", "inputs:\n  version:\n    default: \"0.1.1\"\n")
	writeTestFile(t, root, "actions/README.md", "with:\n    version: 0.1.1\n")

	if err := syncReleaseVersion(root); err != nil {
		t.Fatal(err)
	}

	readme := readTestFile(t, root, "README.md")
	for _, want := range []string{"@v2.3.4", ":v2.3.4", "ref: v2.3.4", "v1.0.0 stays unchanged"} {
		if !strings.Contains(readme, want) {
			t.Errorf("README.md missing %q:\n%s", want, readme)
		}
	}
	security := readTestFile(t, root, "SECURITY.md")
	if !strings.Contains(security, "latest `v2.3.x` release") {
		t.Fatalf("SECURITY.md not updated:\n%s", security)
	}
	for _, name := range []string{"actions/setup/action.yml", "actions/check/action.yml", "actions/README.md"} {
		content := readTestFile(t, root, name)
		if !strings.Contains(content, "2.3.4") {
			t.Fatalf("%s not updated:\n%s", name, content)
		}
	}
}

func TestSyncReleaseVersionRejectsInvalidVersion(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "VERSION", "v1.2.3\n")
	if err := syncReleaseVersion(root); err == nil {
		t.Fatal("expected invalid VERSION to fail")
	}
}

func writeTestFile(t *testing.T, root, name, content string) {
	t.Helper()
	path := filepath.Join(root, name)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, root, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, name))
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
