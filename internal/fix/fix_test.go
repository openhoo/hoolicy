package fix

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

func TestBuildPreviewAndApply(t *testing.T) {
	t.Parallel()
	root := cleanGitRepository(t, map[string]string{"version.json": "{\"version\": 1}\n"})
	old := []byte("{\"version\": 1}\n")
	start := strings.Index(string(old), "1")
	finding := sdk.Finding{RuleID: "demo.version", Fix: &sdk.Fix{Edits: []sdk.Edit{{
		Path: "version.json", ExpectedSHA256: digest(old), Start: start, End: start + 1, Replacement: []byte("2"),
	}}}}
	plan, err := Build(root, []sdk.Finding{finding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if diff := plan.Diff(); !strings.Contains(diff, "-{\"version\": 1}") || !strings.Contains(diff, "+{\"version\": 2}") {
		t.Fatalf("unexpected diff:\n%s", diff)
	}
	if err := plan.Apply(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(root, "version.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "{\"version\": 2}\n" {
		t.Fatalf("unexpected fixed content: %s", data)
	}
}

func TestFixGuardsDirtyChangedAndSymlinkTargets(t *testing.T) {
	t.Parallel()
	root := cleanGitRepository(t, map[string]string{"tracked.txt": "old\n"})
	edit := sdk.Edit{Path: "tracked.txt", ExpectedSHA256: digest([]byte("old\n")), Start: 0, End: 3, Replacement: []byte("new")}
	finding := sdk.Finding{RuleID: "demo.edit", Fix: &sdk.Fix{Edits: []sdk.Edit{edit}}}
	plan, err := Build(root, []sdk.Finding{finding}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := plan.Apply(); err == nil || !strings.Contains(err.Error(), "changed after preview") {
		t.Fatalf("expected preview hash guard, got %v", err)
	}
	if _, err := Build(root, []sdk.Finding{finding}, nil); err == nil || !strings.Contains(err.Error(), "dirty target") {
		t.Fatalf("expected dirty target guard, got %v", err)
	}

	outside := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(root, "linked")); err != nil {
		t.Fatal(err)
	}
	create := sdk.Finding{RuleID: "demo.create", Fix: &sdk.Fix{Edits: []sdk.Edit{{Path: "linked/new.txt", ExpectedSHA256: "missing", Replacement: []byte("no")}}}}
	if _, err := Build(root, []sdk.Finding{create}, nil); err == nil || !strings.Contains(err.Error(), "unsafe fix path") {
		t.Fatalf("expected symlink guard, got %v", err)
	}
}

func TestBuildUsesPureGoGitStatusFallback(t *testing.T) {
	root := cleanGitRepository(t, map[string]string{"tracked.txt": "old\n"})
	t.Setenv("PATH", "")
	edit := sdk.Edit{Path: "tracked.txt", ExpectedSHA256: digest([]byte("old\n")), Start: 0, End: 3, Replacement: []byte("new")}
	finding := sdk.Finding{RuleID: "demo.edit", Fix: &sdk.Fix{Edits: []sdk.Edit{edit}}}
	if _, err := Build(root, []sdk.Finding{finding}, nil); err != nil {
		t.Fatalf("clean fallback target rejected: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("changed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Build(root, []sdk.Finding{finding}, nil); err == nil || !strings.Contains(err.Error(), "dirty target") {
		t.Fatalf("expected fallback dirty-target rejection, got %v", err)
	}
}

func TestApplyBindsEmptyFileExistence(t *testing.T) {
	t.Parallel()
	root := cleanGitRepository(t, map[string]string{"anchor.txt": "anchor\n"})
	create := sdk.Finding{RuleID: "demo.create", Fix: &sdk.Fix{Edits: []sdk.Edit{{
		Path: "new.txt", ExpectedSHA256: "missing", Start: 0, End: 0, Replacement: []byte("created\n"),
	}}}}
	createPlan, err := Build(root, []sdk.Finding{create}, nil)
	if err != nil {
		t.Fatal(err)
	}
	newPath := filepath.Join(root, "new.txt")
	if err := os.WriteFile(newPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := createPlan.Apply(); err == nil || !strings.Contains(err.Error(), "changed after preview") {
		t.Fatalf("expected newly appeared empty file rejection, got %v", err)
	}

	existingRoot := cleanGitRepository(t, map[string]string{"empty.txt": ""})
	update := sdk.Finding{RuleID: "demo.update", Fix: &sdk.Fix{Edits: []sdk.Edit{{
		Path: "empty.txt", ExpectedSHA256: digest(nil), Start: 0, End: 0, Replacement: []byte("updated\n"),
	}}}}
	updatePlan, err := Build(existingRoot, []sdk.Finding{update}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(existingRoot, "empty.txt")); err != nil {
		t.Fatal(err)
	}
	if err := updatePlan.Apply(); err == nil || !strings.Contains(err.Error(), "changed after preview") {
		t.Fatalf("expected deleted empty file rejection, got %v", err)
	}
}

func cleanGitRepository(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	runGit(t, root, "init", "-q", "-b", "main")
	runGit(t, root, "config", "user.name", "Hoolicy Tests")
	runGit(t, root, "config", "user.email", "tests@hoolicy.invalid")
	for path, body := range files {
		absolute := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(absolute, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	runGit(t, root, "add", ".")
	runGit(t, root, "commit", "-qm", "test: fixture")
	return root
}

func runGit(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", append([]string{"-C", root}, args...)...)
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v: %s", args, err, output)
	}
}
