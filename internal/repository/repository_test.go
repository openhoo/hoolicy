package repository

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
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

func TestRepositoryMatchValidatesGlobsWithoutFiles(t *testing.T) {
	t.Parallel()
	repo := &Repository{}
	if _, err := repo.Match([]string{"[broken"}, nil); err == nil {
		t.Fatal("expected invalid include glob error")
	}
	if _, err := repo.Match([]string{"**/*"}, []string{"{broken}"}); err == nil {
		t.Fatal("expected invalid exclude glob error")
	}
}

func TestRepositoryReadUsesOpenedSnapshot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "policy.json")
	if err := os.WriteFile(path, []byte("before\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	repo, err := Open(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("after\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := repo.Read("policy.json")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := string(file.Data), "before\n"; got != want {
		t.Fatalf("Read() = %q, want opened snapshot %q", got, want)
	}
}

func TestInspectGit(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	path := filepath.Join(root, "README.md")
	if err := os.WriteFile(path, []byte("one\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "README.md")
	runGit(t, root, "commit", "-m", "first subject")
	base := runGit(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(path, []byte("two\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "commit", "-am", "second subject")
	head := runGit(t, root, "rev-parse", "HEAD")

	context := inspectGit(root, Options{BaseSHA: base})
	if context.Branch != "main" || context.Commit != head || context.Dirty {
		t.Fatalf("unexpected Git context: %#v", context)
	}
	if len(context.CommitSubjects) != 1 || context.CommitSubjects[0].SHA != head || context.CommitSubjects[0].Subject != "second subject" {
		t.Fatalf("unexpected commits: %#v", context.CommitSubjects)
	}

	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if context := inspectGit(root, Options{}); !context.Dirty {
		t.Fatalf("expected dirty Git context: %#v", context)
	}
}

func BenchmarkRepositoryMatch(b *testing.B) {
	files := make([]sdk.File, 20_000)
	for index := range files {
		files[index].Path = fmt.Sprintf("services/service-%05d/%s", index, []string{"main.go", "config.yaml", "README.md"}[index%3])
	}
	repo := &Repository{files: files}
	include := []string{"**/*.go", "**/*.yaml", "docs/**/*", "{Dockerfile,Containerfile}"}
	exclude := []string{"vendor/**/*", "**/generated/**/*"}
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, err := repo.Match(include, exclude); err != nil {
			b.Fatal(err)
		}
	}
}

func runGit(t *testing.T, root string, args ...string) string {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %s: %v: %s", strings.Join(args, " "), err, output)
	}
	return strings.TrimSpace(string(output))
}
