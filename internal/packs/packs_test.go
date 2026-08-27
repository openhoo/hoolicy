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
	if err := config.SaveLock(filepath.Join(root, config.DefaultLockfile), config.Lock{Version: 1, Packs: []config.LockedPack{{
		Name: "stale", Git: remote, Ref: "main", Commit: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64), Vendor: ".hoolicy/vendor/stale",
	}}}); err != nil {
		t.Fatal(err)
	}
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

func TestResolveRejectsStaleLockWithoutRemotePacks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	lock := config.Lock{Version: 1, Packs: []config.LockedPack{{
		Name: "stale", Git: "https://example.com/policy.git", Ref: "v1.0.0",
		Commit: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64), Vendor: ".hoolicy/vendor/stale",
	}}}
	if err := config.SaveLock(filepath.Join(root, config.DefaultLockfile), lock); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "consumer", Root: root}
	if _, err := Resolve(project); err == nil || !strings.Contains(err.Error(), "stale pack") {
		t.Fatalf("expected stale lock rejection, got %v", err)
	}
}

func TestUpdateLockValidatesSelectionBeforeSync(t *testing.T) {
	t.Parallel()
	project := &config.Project{Version: 1, Project: "consumer", Root: t.TempDir(), Packs: []config.PackRef{{Name: "demo", Git: "https://example.com/policy.git", Ref: "main"}}}
	if _, err := UpdateLock(project, []string{"demo", "demo"}); err == nil || !strings.Contains(err.Error(), "more than once") {
		t.Fatalf("expected duplicate selection rejection, got %v", err)
	}
	if _, err := UpdateLock(project, []string{"unknown"}); err == nil || !strings.Contains(err.Error(), "not a configured remote pack") {
		t.Fatalf("expected unknown selection rejection, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(project.Root, config.DefaultLockfile)); !os.IsNotExist(err) {
		t.Fatalf("selection validation should not touch lockfile, got %v", err)
	}
}

func TestRemotePackRejectsSymlinkedSubdirBeforeManifestRead(t *testing.T) {
	t.Parallel()
	outside := t.TempDir()
	writePackFile(t, outside, "pack.yaml", `version: 1
name: demo
release: 1.0.0
description: Outside pack.
rules:
  - id: demo.rule
    title: Demo
    description: Demo rule.
    rationale: Test boundary.
    remediation: Fix boundary.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require, message: Missing}
`)
	remote := t.TempDir()
	runPackGit(t, remote, "init", "-q", "-b", "main")
	runPackGit(t, remote, "config", "user.name", "Hoolicy Tests")
	runPackGit(t, remote, "config", "user.email", "tests@hoolicy.invalid")
	if err := os.Symlink(outside, filepath.Join(remote, "linked")); err != nil {
		t.Fatal(err)
	}
	runPackGit(t, remote, "add", "linked")
	runPackGit(t, remote, "commit", "-qm", "test: symlinked pack")
	root := t.TempDir()
	project := &config.Project{Version: 1, Project: "consumer", Root: root, Packs: []config.PackRef{{Name: "demo", Git: remote, Ref: "main", Subdir: "linked"}}}
	if _, err := Sync(project, "demo"); err == nil || !strings.Contains(err.Error(), "symbolic link in repository path") {
		t.Fatalf("expected pre-read subdir rejection, got %v", err)
	}
}

func TestReplaceDirectoryPreservesUnrelatedLegacyBackup(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	source := filepath.Join(root, "source")
	target := filepath.Join(root, "vendor")
	legacyBackup := target + ".hoolicy-backup"
	writePackFile(t, source, "value.txt", "new")
	writePackFile(t, target, "value.txt", "old")
	writePackFile(t, legacyBackup, "recovery.txt", "keep")
	if err := replaceDirectory(source, target); err != nil {
		t.Fatal(err)
	}
	assertPackFile(t, filepath.Join(target, "value.txt"), "new")
	assertPackFile(t, filepath.Join(legacyBackup, "recovery.txt"), "keep")
}

func TestReplaceDirectoryRestoresTargetAfterInstallFailure(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	target := filepath.Join(root, "vendor")
	writePackFile(t, target, "value.txt", "old")
	if err := replaceDirectory(filepath.Join(root, "missing"), target); err == nil {
		t.Fatal("expected replacement failure")
	}
	assertPackFile(t, filepath.Join(target, "value.txt"), "old")
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

func assertPackFile(t *testing.T, path, want string) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != want {
		t.Fatalf("%s = %q, want %q", path, data, want)
	}
}

func runPackGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
