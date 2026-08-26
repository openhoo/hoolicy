package packs

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
)

func TestDigestRejectsSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePackFile(t, root, "a.txt", "a")
	first, err := Digest(root)
	if err != nil {
		t.Fatal(err)
	}
	second, err := Digest(root)
	if err != nil || first != second || !strings.HasPrefix(first, "sha256:") {
		t.Fatalf("unstable digest: %q %q %v", first, second, err)
	}
	if err := os.Symlink(filepath.Join(root, "a.txt"), filepath.Join(root, "link")); err != nil {
		t.Fatal(err)
	}
	if _, err := Digest(root); err == nil {
		t.Fatal("expected symlink rejection")
	}
}

func TestRemotePackSyncLocksAndChecksOffline(t *testing.T) {
	t.Parallel()
	remote := t.TempDir()
	runPackGit(t, remote, "init", "-q", "-b", "main")
	runPackGit(t, remote, "config", "user.name", "Hoolicy Tests")
	runPackGit(t, remote, "config", "user.email", "tests@hoolicy.invalid")
	writePackFile(t, remote, "pack.yaml", `version: 1
name: demo
release: 0.1.0
description: Demo remote pack.
rules:
  - id: demo.readme
    title: README exists
    description: Requires a README.
    rationale: Documentation matters.
    remediation: Add README.md.
    severity: error
    kind: files
    files: [README.md]
    spec:
      mode: require
      message: Missing README
`)
	runPackGit(t, remote, "add", ".")
	runPackGit(t, remote, "commit", "-qm", "feat: add pack")

	root := t.TempDir()
	project := &config.Project{Version: 1, Project: "consumer", Root: root, Path: filepath.Join(root, config.DefaultFilename), Packs: []config.PackRef{{Name: "demo", Git: remote, Ref: "main"}}}
	lock, err := UpdateLock(project, []string{"demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Packs) != 1 || len(lock.Packs[0].Commit) != 40 {
		t.Fatalf("unexpected lock: %#v", lock)
	}
	rules, err := Resolve(project)
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].ID != "demo.readme" {
		t.Fatalf("unexpected resolved rules: %#v", rules)
	}
	vendored := filepath.Join(root, filepath.FromSlash(lock.Packs[0].Vendor), "pack.yaml")
	if err := os.WriteFile(vendored, []byte("tampered\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Resolve(project); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("expected offline digest mismatch, got %v", err)
	}
}

func writePackFile(t *testing.T, root, path, body string) {
	t.Helper()
	absolute := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func runPackGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
