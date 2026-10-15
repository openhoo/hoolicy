package safepath

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWritableRejectsSymlinkComponents(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Writable(root, "linked/new.txt"); !errors.Is(err, ErrSymlink) {
		t.Fatalf("expected ErrSymlink, got %v", err)
	}
	clean, absolute, err := Writable(root, "new/nested.txt")
	if err != nil {
		t.Fatal(err)
	}
	if clean != "new/nested.txt" || absolute != filepath.Join(root, "new", "nested.txt") {
		t.Fatalf("unexpected resolution: %q %q", clean, absolute)
	}
}

func TestPortablePathsRejectWindowsAndBackslashForms(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	for _, path := range []string{"C:/outside", `C:\outside`, `..\outside`, "/outside"} {
		if _, _, err := Writable(root, path); err == nil {
			t.Fatalf("Writable accepted unsafe path %q", path)
		}
		if _, _, err := Existing(root, path); err == nil {
			t.Fatalf("Existing accepted unsafe path %q", path)
		}
	}
}

func TestRelativeDoesNotTouchFilesystem(t *testing.T) {
	t.Parallel()
	for _, path := range []string{"committed.txt", "nested/../committed.txt"} {
		clean, err := Relative(path)
		if err != nil || clean != "committed.txt" {
			t.Fatalf("Relative(%q) = %q, %v", path, clean, err)
		}
	}
	if _, err := Relative("../missing.txt"); err == nil {
		t.Fatal("Relative accepted traversal")
	}
}

func TestGitMetadataPathRecognizesPortableAliases(t *testing.T) {
	t.Parallel()
	for _, path := range []string{".git/config", "nested/.git", ".GIT/hooks/pre-commit", ".git./config", ".git::$DATA"} {
		if !GitMetadataPath(path) {
			t.Errorf("metadata path %q not recognized", path)
		}
	}
	for _, path := range []string{".github/workflows/check.yaml", "git/config", ".gitignore", ".gitmodules"} {
		if GitMetadataPath(path) {
			t.Errorf("source path %q identified as Git metadata", path)
		}
	}
}

func TestResolverMatchesExisting(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	for _, path := range []string{"a/b/file.txt", "a/file.txt", "plain.txt"} {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(path), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(root, "plain.txt"), filepath.Join(root, "a", "alias.txt")); err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(root)
	// Repeat every path so that later lookups use cached directory results.
	paths := []string{"a/b/file.txt", "a/file.txt", "a/./b/../file.txt", "plain.txt", "linked/secret.txt", "a/alias.txt",
		"plain.txt/child", "missing/file.txt", "a/missing.txt", "../escape", "/absolute"}
	for _, path := range append(paths, paths...) {
		wantClean, wantAbsolute, wantErr := Existing(root, path)
		clean, absolute, info, err := resolver.Existing(path)
		if clean != wantClean || absolute != wantAbsolute || fmt.Sprint(err) != fmt.Sprint(wantErr) || errors.Is(err, ErrSymlink) != errors.Is(wantErr, ErrSymlink) || errors.Is(err, os.ErrNotExist) != errors.Is(wantErr, os.ErrNotExist) {
			t.Fatalf("Resolver.Existing(%q) = %q, %q, %v; Existing = %q, %q, %v", path, clean, absolute, err, wantClean, wantAbsolute, wantErr)
		}
		if err != nil {
			continue
		}
		want, statErr := os.Lstat(wantAbsolute)
		if statErr != nil || !os.SameFile(info, want) {
			t.Fatalf("Resolver.Existing(%q) returned stale file information: %v", path, statErr)
		}
	}
}
