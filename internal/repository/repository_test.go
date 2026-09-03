package repository

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
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

func TestRuleInputCacheBindsContentAndPolicyDigest(t *testing.T) {
	t.Parallel()
	content := []byte(t.Name())
	file := sdk.File{Path: "service/input.json", Mode: 0o644, Data: content}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "service"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, file.Path), content, 0o644); err != nil {
		t.Fatal(err)
	}
	base := &Repository{root: root, files: []sdk.File{file}, byPath: map[string]sdk.File{file.Path: file}}
	policy := "sha256:" + strings.Repeat("a", 64) + t.Name()

	first := Cached(base, policy)
	if _, err := first.Match([]string{"**/*.json"}, nil); err != nil {
		t.Fatal(err)
	}
	second := Cached(base, policy)
	if _, err := second.Match([]string{"**/*.json"}, nil); err != nil {
		t.Fatal(err)
	}
	if measured := second.(interface{ InputCacheHits() int }).InputCacheHits(); measured != 1 {
		t.Fatalf("same content and policy did not hit cache: %d", measured)
	}

	changedFile := file
	changedFile.Data = append(append([]byte(nil), content...), '!')
	changed := &Repository{root: base.root, files: []sdk.File{changedFile}, byPath: map[string]sdk.File{changedFile.Path: changedFile}}
	for name, candidate := range map[string]sdk.Repository{
		"content": Cached(changed, policy),
		"policy":  Cached(base, policy+"-changed"),
	} {
		if _, err := candidate.Match([]string{"**/*.json"}, nil); err != nil {
			t.Fatal(err)
		}
		if measured := candidate.(interface{ InputCacheHits() int }).InputCacheHits(); measured != 0 {
			t.Fatalf("%s change reused stale cache: %d", name, measured)
		}
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

	context, err := inspectGit(root, Options{BaseSHA: base})
	if err != nil {
		t.Fatal(err)
	}
	if context.Branch != "main" || context.Commit != head || context.Dirty {
		t.Fatalf("unexpected Git context: %#v", context)
	}
	if len(context.CommitSubjects) != 1 || context.CommitSubjects[0].SHA != head || context.CommitSubjects[0].Subject != "second subject" {
		t.Fatalf("unexpected commits: %#v", context.CommitSubjects)
	}

	if err := os.WriteFile(filepath.Join(root, "untracked.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	context, err = inspectGit(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if !context.Dirty {
		t.Fatalf("expected dirty Git context: %#v", context)
	}
}

func TestRepositoryUsesPureGoGitFallback(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("secret.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".gitignore", "tracked.txt")
	runGit(t, root, "commit", "-m", "test: fallback")
	if err := os.WriteFile(filepath.Join(root, "secret.json"), []byte(`{"token":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("visible\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	repo, err := Open(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(repo.AllFiles()))
	for _, file := range repo.AllFiles() {
		paths = append(paths, file.Path)
	}
	if slices.Contains(paths, "secret.json") || !slices.Contains(paths, "tracked.txt") || !slices.Contains(paths, "visible.txt") {
		t.Fatalf("unexpected fallback files: %#v", paths)
	}
	context := repo.Git()
	if context.Branch != "main" || context.Commit == "" || len(context.CommitSubjects) != 1 || context.CommitSubjects[0].Subject != "test: fallback" || !context.Dirty {
		t.Fatalf("unexpected fallback Git context: %#v", context)
	}
}

func TestRepositoryPureGoFallbackSupportsUnbornRepository(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("secret.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "secret.json"), []byte(`{"token":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("visible\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	repo, err := Open(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(repo.AllFiles()))
	for _, file := range repo.AllFiles() {
		paths = append(paths, file.Path)
	}
	if slices.Contains(paths, "secret.json") || !slices.Contains(paths, ".gitignore") || !slices.Contains(paths, "visible.txt") {
		t.Fatalf("unexpected fallback files: %#v", paths)
	}
	context := repo.Git()
	if context.Branch != "main" || context.Commit != "" || !context.Dirty {
		t.Fatalf("unexpected fallback Git context: %#v", context)
	}
}

func TestRepositoryPureGoFallbackSupportsUnreadableIndex(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix index permission bits")
	}
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte("secret.json\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", ".gitignore", "tracked.txt")
	runGit(t, root, "commit", "-m", "test: private index")
	if err := os.WriteFile(filepath.Join(root, "secret.json"), []byte(`{"token":"hidden"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "visible.txt"), []byte("visible\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(root, ".git", "index"), 0); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", "")
	repo, err := Open(root, Options{})
	if err != nil {
		t.Fatal(err)
	}
	paths := make([]string, 0, len(repo.AllFiles()))
	for _, file := range repo.AllFiles() {
		paths = append(paths, file.Path)
	}
	if slices.Contains(paths, "secret.json") || !slices.Contains(paths, "tracked.txt") || !slices.Contains(paths, "visible.txt") {
		t.Fatalf("unexpected fallback files: %#v", paths)
	}
	context := repo.Git()
	if context.Commit == "" || !context.Dirty || context.Properties["gitIndexReadable"] != false {
		t.Fatalf("unexpected conservative Git context: %#v", context)
	}
}

func TestRepositoryPureGoFallbackSupportsLinkedWorktree(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "test: linked worktree")
	linked := filepath.Join(t.TempDir(), "linked")
	runGit(t, root, "worktree", "add", "-b", "feature", linked)
	t.Setenv("PATH", "")
	repo, err := Open(linked, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if context := repo.Git(); context.Branch != "feature" || context.Commit == "" || context.Dirty {
		t.Fatalf("unexpected fallback Git context: %#v", context)
	}
	metadata, err := os.ReadFile(filepath.Join(linked, ".git"))
	if err != nil {
		t.Fatal(err)
	}
	gitDir := strings.TrimSpace(strings.TrimPrefix(string(metadata), "gitdir: "))
	commonDir := filepath.Join(gitDir, "commondir")
	moved := commonDir + ".moved"
	if err := os.Rename(commonDir, moved); err != nil {
		t.Fatalf("linked-worktree metadata handle remains open: %v", err)
	}
	if err := os.Rename(moved, commonDir); err != nil {
		t.Fatalf("restore linked-worktree metadata: %v", err)
	}
}

func TestRepositoryRejectsInvalidBaseRevision(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt")
	runGit(t, root, "commit", "-m", "test: base")
	if _, err := Open(root, Options{BaseSHA: "not-a-revision"}); err == nil || !strings.Contains(err.Error(), "inspect Git repository") {
		t.Fatalf("expected invalid base error, got %v", err)
	}
	if _, err := Open(root, Options{BaseSHA: "--all"}); err == nil || !strings.Contains(err.Error(), "unsafe base revision") {
		t.Fatalf("expected option-like base rejection, got %v", err)
	}
}

func TestOpenRevisionReadsCompleteHistoricalSnapshot(t *testing.T) {
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("before\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("tracked.txt", filepath.Join(root, "link.txt")); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "tracked.txt", "link.txt")
	// Windows worktrees do not infer the executable bit from NTFS metadata.
	// Set the index bit explicitly so the committed tree exercises mode recovery
	// on every supported platform.
	runGit(t, root, "update-index", "--chmod=+x", "tracked.txt")
	runGit(t, root, "commit", "-m", "test: base snapshot")
	base := runGit(t, root, "rev-parse", "HEAD")
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("after\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new.txt"), []byte("new\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(root, "tracked.txt")); err != nil {
		t.Fatal(err)
	}
	repo, err := OpenRevision(root, base, Options{})
	if err != nil {
		t.Fatal(err)
	}
	files := repo.AllFiles()
	if len(files) != 1 || files[0].Path != "tracked.txt" || string(files[0].Data) != "before\n" || files[0].Mode&0o111 == 0 {
		t.Fatalf("unexpected revision files: %#v", files)
	}
	file, err := repo.Read("tracked.txt")
	if err != nil || string(file.Data) != "before\n" {
		t.Fatalf("historical read failed after worktree deletion: %#v %v", file, err)
	}
	if repo.Git().Commit != base || repo.Git().Dirty {
		t.Fatalf("unexpected revision Git context: %#v", repo.Git())
	}
	if _, err := OpenRevision(root, "--all", Options{}); err == nil || !strings.Contains(err.Error(), "unsafe revision") {
		t.Fatalf("expected unsafe revision rejection, got %v", err)
	}
}

func TestOpenRevisionRejectsUnsafeGitTreePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create a filename containing a backslash")
	}
	root := t.TempDir()
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	unsafeName := `unsafe\name`
	if err := os.WriteFile(filepath.Join(root, unsafeName), []byte("unsafe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", unsafeName)
	runGit(t, root, "commit", "-m", "test: unsafe tree path")
	revision := runGit(t, root, "rev-parse", "HEAD")
	if _, err := OpenRevision(root, revision, Options{}); err == nil || !strings.Contains(err.Error(), "unsafe Git tree path") {
		t.Fatalf("unsafe Git tree path accepted: %v", err)
	}
}

func TestOpenRevisionIgnoresUnsafeSiblingOutsideScope(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows cannot create a filename containing a backslash")
	}
	root := t.TempDir()
	project := filepath.Join(root, "project")
	if err := os.MkdirAll(project, 0o755); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "init", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Test")
	runGit(t, root, "config", "user.email", "hoolicy@example.com")
	if err := os.WriteFile(filepath.Join(project, "tracked.txt"), []byte("tracked\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(root, "sibling")
	if err := os.MkdirAll(sibling, 0o755); err != nil {
		t.Fatal(err)
	}
	unsafeName := `unsafe\name`
	if err := os.WriteFile(filepath.Join(sibling, unsafeName), []byte("unsafe\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	runGit(t, root, "add", "project/tracked.txt", "sibling/unsafe\\name")
	runGit(t, root, "commit", "-m", "test: scoped unsafe tree path")
	revision := runGit(t, root, "rev-parse", "HEAD")
	repo, err := OpenRevision(project, revision, Options{})
	if err != nil {
		t.Fatal(err)
	}
	files := repo.AllFiles()
	if len(files) != 1 || files[0].Path != "tracked.txt" || string(files[0].Data) != "tracked\n" {
		t.Fatalf("unexpected scoped revision files: %#v", files)
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
