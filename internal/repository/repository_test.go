package repository

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGlobMatching(t *testing.T) {
	t.Parallel()
	tests := []struct {
		path, pattern string
		want          bool
	}{
		{"README.md", "**/*.md", true},
		{"docs/guide.md", "**/*.md", true},
		{"Dockerfile", "**/{Dockerfile,Containerfile}", true},
		{"src/main.go", "src/??in.go", true},
		{"src/main.go", "*.go", false},
	}
	for _, test := range tests {
		got, err := Matches(test.path, []string{test.pattern})
		if err != nil {
			t.Fatal(err)
		}
		if got != test.want {
			t.Fatalf("Matches(%q, %q) = %v, want %v", test.path, test.pattern, got, test.want)
		}
	}
	if _, err := Matches("a", []string{"[broken"}); err == nil {
		t.Fatal("expected invalid glob error")
	}
}

func TestRepositoryDoesNotFollowSymlinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "safe.txt"), []byte("safe"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "secret.txt"), filepath.Join(root, "secret.txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	repo, err := Open(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(repo.AllFiles()) != 1 || repo.AllFiles()[0].Path != "safe.txt" {
		t.Fatalf("unexpected discovered files: %#v", repo.AllFiles())
	}
	for _, path := range []string{"secret.txt", "escape/secret.txt", "../secret.txt"} {
		if _, err := repo.Read(path); err == nil {
			t.Fatalf("expected unsafe read %q to fail", path)
		}
	}
}
