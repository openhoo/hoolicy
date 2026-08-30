package packs

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/packarchive"
)

func TestReleaseLessIncludesPrereleasePrecedence(t *testing.T) {
	t.Parallel()
	if !releaseLess("1.2.3-rc.1", "1.2.3") || releaseLess("1.2.3", "1.2.3-rc.1") || !releaseLess("1.2.3-rc.1", "1.2.3-rc.2") {
		t.Fatal("release downgrade comparison ignored prerelease precedence")
	}
}

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

func TestDigestEnforcesPackFileLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "oversized.bin")
	writePackFile(t, root, "oversized.bin", "")
	if err := os.Truncate(path, packarchive.MaxFileSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := Digest(root); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized pack file accepted: %v", err)
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
	writePackFile(t, root, ".hoolicy/vendor/stale/pack.yaml", "stale")
	lock, err := UpdateLock(project, []string{"demo"})
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Packs) != 1 || len(lock.Packs[0].Commit) != 40 {
		t.Fatalf("unexpected lock: %#v", lock)
	}
	if _, err := os.Lstat(filepath.Join(root, ".hoolicy", "vendor", "stale")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale vendor survived lock pruning: %v", err)
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

func TestUpdateLockRefusesNonCanonicalStaleVendorPath(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writePackFile(t, root, "README.md", "keep")
	lock := config.Lock{Version: 1, Packs: []config.LockedPack{{
		Name: "stale", Git: "https://example.com/policy.git", Ref: "v1.0.0",
		Commit: strings.Repeat("a", 40), Digest: "sha256:" + strings.Repeat("b", 64), Vendor: "README.md",
	}}}
	if err := config.SaveLock(filepath.Join(root, config.DefaultLockfile), lock); err != nil {
		t.Fatal(err)
	}
	project := &config.Project{Version: 1, Project: "consumer", Root: root}
	if _, err := UpdateLock(project, nil); err == nil || !strings.Contains(err.Error(), "non-canonical vendor path") {
		t.Fatalf("unsafe stale vendor path accepted: %v", err)
	}
	assertPackFile(t, filepath.Join(root, "README.md"), "keep")
}

func TestUpdateLockRejectsDowngradeBeforeMutatingVendorOrLock(t *testing.T) {
	t.Parallel()
	remote := t.TempDir()
	runPackGit(t, remote, "init", "-q", "-b", "main")
	runPackGit(t, remote, "config", "user.name", "Hoolicy Tests")
	runPackGit(t, remote, "config", "user.email", "tests@hoolicy.invalid")
	manifest := func(release string) string {
		return `version: 1
name: demo
release: ` + release + `
description: Downgrade safety fixture.
rules:
  - id: demo.readme
    title: README exists
    description: Requires a README.
    rationale: Documentation matters.
    remediation: Add README.md.
    severity: error
    kind: files
    files: [README.md]
    spec: {mode: require, message: Missing README}
`
	}
	writePackFile(t, remote, "pack.yaml", manifest("1.0.0"))
	runPackGit(t, remote, "add", ".")
	runPackGit(t, remote, "commit", "-qm", "feat: release 1.0.0")
	root := t.TempDir()
	project := &config.Project{Version: 1, Project: "consumer", Root: root, Packs: []config.PackRef{{Name: "demo", Git: remote, Ref: "main"}}}
	if _, err := UpdateLock(project, []string{"demo"}); err != nil {
		t.Fatal(err)
	}
	vendorPath := filepath.Join(root, ".hoolicy", "vendor", "demo", "pack.yaml")
	beforeVendor, err := os.ReadFile(vendorPath)
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(root, config.DefaultLockfile)
	beforeLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	writePackFile(t, remote, "pack.yaml", manifest("0.9.0"))
	runPackGit(t, remote, "add", ".")
	runPackGit(t, remote, "commit", "-qm", "test: attempted downgrade")
	if _, err := UpdateLock(project, []string{"demo"}); err == nil || !strings.Contains(err.Error(), "downgrade") {
		t.Fatalf("downgrade accepted: %v", err)
	}
	afterVendor, err := os.ReadFile(vendorPath)
	if err != nil {
		t.Fatal(err)
	}
	afterLock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(afterVendor) != string(beforeVendor) || string(afterLock) != string(beforeLock) {
		t.Fatal("rejected downgrade mutated vendor or lock")
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

func TestSanitizeGitOutputRedactsControlsCredentialsAndLength(t *testing.T) {
	t.Parallel()
	input := "first\nsecond\nhttps://secret@example.com/repo\x1b[31m\n" + strings.Repeat("x", 2048)
	output := sanitizeGitOutput(input)
	if strings.Contains(output, "secret") || strings.ContainsRune(output, '\x1b') || len([]rune(output)) > 1027 {
		t.Fatalf("unsafe Git output: %q", output)
	}
	if !strings.Contains(output, "https://<redacted>@example.com/repo") {
		t.Fatalf("credential redaction missing: %q", output)
	}
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

func TestInstallAcquiredRollsBackAllVendorsWhenLockCommitFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	firstVendor := filepath.Join(root, "vendor", "first")
	secondVendor := filepath.Join(root, "vendor", "second")
	firstStage := filepath.Join(root, "vendor", ".first-stage")
	secondStage := filepath.Join(root, "vendor", ".second-stage")
	writePackFile(t, firstVendor, "value.txt", "first-old")
	writePackFile(t, firstStage, "value.txt", "first-new")
	writePackFile(t, secondStage, "value.txt", "second-new")
	packs := []*acquiredPack{{staged: firstStage, vendor: firstVendor}, {staged: secondStage, vendor: secondVendor}}
	if err := installAcquired(packs, nil, func() error { return errors.New("lock commit failed") }); err == nil || !strings.Contains(err.Error(), "lock commit failed") {
		t.Fatalf("commit failure ignored: %v", err)
	}
	assertPackFile(t, filepath.Join(firstVendor, "value.txt"), "first-old")
	if _, err := os.Lstat(secondVendor); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("new vendor survived rollback: %v", err)
	}
}

func TestInstallAcquiredRestoresRemovedVendorsWhenLockCommitFails(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	vendor := filepath.Join(root, "vendor", "stale")
	writePackFile(t, vendor, "value.txt", "old")
	if err := installAcquired(nil, []string{vendor}, func() error { return errors.New("lock commit failed") }); err == nil || !strings.Contains(err.Error(), "lock commit failed") {
		t.Fatalf("commit failure ignored: %v", err)
	}
	assertPackFile(t, filepath.Join(vendor, "value.txt"), "old")
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
