package safepath

import (
	"errors"
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
