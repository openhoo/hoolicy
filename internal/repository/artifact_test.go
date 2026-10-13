package repository

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestArtifactOutputsRequireExcludedSourcePaths(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	if _, err := ArtifactOutputPath(root, filepath.Join(outside, ".git", "info", "evidence.json")); err == nil || !strings.Contains(err.Error(), "Git metadata") {
		t.Fatalf("outside Git metadata output accepted: %v", err)
	}
	if _, err := ArtifactOutputPath(root, filepath.Join(root, "new", "evidence.json")); err == nil || !strings.Contains(err.Error(), "outside") {
		t.Fatalf("plain source output accepted: %v", err)
	}
	if _, err := os.Lstat(filepath.Join(root, "new")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("preflight created an output directory: %v", err)
	}
	if _, err := ArtifactOutputPath(root, filepath.Join(outside, "new", "evidence.json")); err != nil {
		t.Fatalf("outside plain source output rejected: %v", err)
	}
	runGit(t, root, "init", "-q", "-b", "main")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("artifacts/\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := ArtifactOutputPath(root, filepath.Join(root, "artifacts", "evidence.json")); err != nil {
		t.Fatalf("ignored artifact output rejected: %v", err)
	}
	// An in-repository alias must not be treated as an outside destination.
	if err := os.Symlink(root, filepath.Join(outside, "source")); err != nil {
		t.Fatal(err)
	}
	if _, err := ArtifactOutputPath(root, filepath.Join(outside, "source", "evidence.json")); err == nil || !strings.Contains(err.Error(), "dirty state") {
		t.Fatalf("symlink parent hid an in-source output: %v", err)
	}
	// Without Git we cannot prove that an in-source output is ignored.
	t.Setenv("PATH", "")
	if _, err := ArtifactOutputPath(root, filepath.Join(root, "artifacts", "evidence.json")); err == nil || !strings.Contains(err.Error(), "cannot verify Git ignore status") {
		t.Fatalf("unverifiable ignore status accepted: %v", err)
	}
	if _, err := ArtifactOutputPath(root, filepath.Join(outside, "evidence.json")); err != nil {
		t.Fatalf("outside artifact output requires Git: %v", err)
	}
}

func TestArtifactOutputsRejectExternalGitMetadataIndirection(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	metadata := filepath.Join(t.TempDir(), "repository-metadata")
	runGit(t, root, "init", "-q", "-b", "main", "--separate-git-dir", metadata)
	if _, err := ArtifactOutputPath(root, filepath.Join(metadata, "info", "evidence.json")); err == nil || !strings.Contains(err.Error(), "Git metadata") {
		t.Fatalf("separate Git directory accepted as artifact output: %v", err)
	}
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, "anchor.txt"), []byte("anchor\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-qm", "test: linked metadata")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, root, "worktree", "add", "--detach", "-q", linked, "HEAD")
	linkedMetadata := runGit(t, linked, "rev-parse", "--absolute-git-dir")
	for _, directory := range []string{metadata, linkedMetadata} {
		if _, err := ArtifactOutputPath(linked, filepath.Join(directory, "evidence.json")); err == nil || !strings.Contains(err.Error(), "Git metadata") {
			t.Errorf("linked Git metadata %s accepted as artifact output: %v", directory, err)
		}
	}
}

func TestArtifactPathContainmentHandlesPlatformAliases(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		if inside, err := PathWithin(`C:\source`, `D:\artifacts\evidence.json`); err != nil || inside {
			t.Fatalf("outside Windows volume: inside=%v err=%v", inside, err)
		}
	}
	if runtime.GOOS == "windows" || runtime.GOOS == "darwin" {
		root := t.TempDir()
		if inside, err := PathWithin(filepath.Join(root, "PolicyPack"), filepath.Join(root, "policypack", "evidence.json")); err != nil || !inside {
			t.Fatalf("case alias escaped pack boundary: inside=%v err=%v", inside, err)
		}
	}
}

func TestCanonicalOutputPathRejectsDanglingParentAliases(t *testing.T) {
	t.Parallel()
	for _, suffix := range []string{"output.json", "nested/output.json"} {
		t.Run(suffix, func(t *testing.T) {
			root := t.TempDir()
			target := filepath.Join(root, "missing")
			alias := filepath.Join(root, "alias")
			if err := os.Symlink(target, alias); err != nil {
				t.Fatal(err)
			}
			if _, err := CanonicalOutputPath(filepath.Join(alias, filepath.FromSlash(suffix))); err == nil || !strings.Contains(err.Error(), "parent symbolic link") {
				t.Fatalf("dangling parent accepted: %v", err)
			}
			if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("preflight created the dangling target: %v", err)
			}
		})
	}
}
