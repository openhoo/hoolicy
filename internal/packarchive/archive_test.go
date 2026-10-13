package packarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestCanonicalArchiveIsDeterministicAndRoundTrips(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "tests"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "pack.yaml"), []byte("version: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tests", "cases.yaml"), []byte("version: 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	first, firstDigest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(filepath.Join(root, "pack.yaml"), timeNow(), timeNow()); err != nil {
		t.Fatal(err)
	}
	second, secondDigest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first, second) || firstDigest != secondDigest {
		t.Fatal("archive depends on timestamps or source modes")
	}
	target := t.TempDir()
	digest, err := Extract(first, target)
	if err != nil {
		t.Fatal(err)
	}
	if digest != firstDigest {
		t.Fatalf("digest mismatch %s != %s", digest, firstDigest)
	}
	data, err := os.ReadFile(filepath.Join(target, "tests", "cases.yaml"))
	if err != nil || string(data) != "version: 1\n" {
		t.Fatalf("unexpected extracted data %q %v", data, err)
	}
}

func TestExtractRejectsTraversalAndLinks(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name string
		kind byte
	}{{"../escape", tar.TypeReg}, {"dir/../../escape", tar.TypeReg}, {"/escape", tar.TypeReg}, {"C:/escape", tar.TypeReg}, {`C:\escape`, tar.TypeReg}, {"link", tar.TypeSymlink}, {"legacy-regular", 0}} {
		var data bytes.Buffer
		gz := gzip.NewWriter(&data)
		tw := tar.NewWriter(gz)
		if err := tw.WriteHeader(&tar.Header{Name: test.name, Typeflag: test.kind, Size: 0}); err != nil {
			t.Fatal(err)
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
		if _, err := Extract(data.Bytes(), t.TempDir()); err == nil {
			t.Fatalf("accepted unsafe %s", test.name)
		}
	}
}

func TestExtractRequiresEmptyTargetAndCanonicalBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	canonical, _, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	nonempty := t.TempDir()
	if err := os.WriteFile(filepath.Join(nonempty, "keep"), []byte("keep"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(canonical, nonempty); err == nil {
		t.Fatal("accepted non-empty extraction target")
	}

	var data bytes.Buffer
	gz := gzip.NewWriter(&data)
	tw := tar.NewWriter(gz)
	body := []byte("version: 1\n")
	if err := tw.WriteHeader(&tar.Header{Name: "pack.yaml", Typeflag: tar.TypeReg, Mode: 0o600, Size: int64(len(body)), ModTime: time.Now()}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := Extract(data.Bytes(), t.TempDir()); err == nil {
		t.Fatal("accepted non-canonical archive metadata")
	}
}

func TestBuildRejectsSymbolicLinks(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside.yaml")
	if err := os.WriteFile(outside, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "pack.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, _, err := Build(root); err == nil {
		t.Fatal("archived symbolic link")
	}
}

func TestMaximumContentSizeRoundTripsWithTarOverhead(t *testing.T) {
	root := t.TempDir()
	payload := make([]byte, MaxFileSize)
	for index := 0; index < MaxTotalSize/MaxFileSize; index++ {
		path := filepath.Join(root, "payload", fmt.Sprintf("%02d.bin", index))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	archive, expectedDigest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	digest, err := Extract(archive, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if digest != expectedDigest {
		t.Fatalf("digest = %s, want %s", digest, expectedDigest)
	}
}

func TestBuildRejectsContentBeyondAggregateLimit(t *testing.T) {
	root := t.TempDir()
	payload := make([]byte, MaxFileSize)
	for index := 0; index <= MaxTotalSize/MaxFileSize; index++ {
		path := filepath.Join(root, fmt.Sprintf("%02d.bin", index))
		if err := os.WriteFile(path, payload, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := Build(root); err == nil || !strings.Contains(err.Error(), "pack content exceeds") {
		t.Fatalf("unexpected aggregate limit result: %v", err)
	}
}

func TestBuildRejectsEmptyPack(t *testing.T) {
	t.Parallel()
	if _, _, err := Build(t.TempDir()); err == nil {
		t.Fatal("built an archive that Extract would reject as empty")
	}
}

func TestBuildExcludesLinkedWorktreeGitIndirection(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "pack.yaml"), []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	want, wantDigest, err := Build(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".git"), []byte("gitdir: /source/.git/worktrees/policy\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, gotDigest, err := Build(root)
	if err != nil || gotDigest != wantDigest || !bytes.Equal(got, want) {
		t.Fatalf("linked worktree metadata entered archive: digest=%s want=%s err=%v", gotDigest, wantDigest, err)
	}
}

func TestValidatePathsBoundsLongPathAllocations(t *testing.T) {
	for _, name := range []string{strings.Repeat("a/", 2000) + "file.yaml", strings.Repeat("a/", 30000) + "file.yaml"} {
		if err := ValidatePaths([]string{name}); err == nil || !strings.Contains(err.Error(), "limits") {
			t.Fatalf("unbounded archive path accepted: bytes=%d err=%v", len(name), err)
		}
		allocations := testing.AllocsPerRun(5, func() {
			if err := ValidatePaths([]string{name}); err == nil {
				panic("unbounded archive path accepted")
			}
		})
		if allocations > 10 {
			t.Fatalf("long-path preflight allocated %.0f objects for %d bytes", allocations, len(name))
		}
	}
	portable := strings.Repeat("a/", MaxPathDepth-1) + "file.yaml"
	if err := ValidatePaths([]string{portable}); err != nil {
		t.Fatalf("maximum supported path depth rejected: %v", err)
	}
}

func TestArchivePathsRejectPortableAliasesAndGitMetadata(t *testing.T) {
	t.Parallel()
	for _, name := range []string{
		".git/config", "nested/.git/config", "nested/.GiT/config", "nested/.git./config",
		"file:stream", "nested/file:stream", "nested/trailing.", "nested/trailing ", ".. /escape",
		"CON", "aux.txt", "nested/PRN.json", "NUL.yaml", "COM1.txt", "lpt9", "COM\u00b9.txt", "LPT\u00b2",
		"control\nname", "wild*card", "wild?card", "less<than", "quote\"name", "pipe|name",
		"nested/.g\u200cit/config", "bad\xffname",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if _, err := safeArchivePath(name); err == nil {
				t.Fatalf("accepted non-portable or reserved archive path %q", name)
			}
			if _, _, err := canonicalArchive([]archiveEntry{{name: name, data: []byte("fixture")}}); err == nil {
				t.Fatalf("built archive with unsafe path %q", name)
			}
		})
	}
	for _, name := range []string{"pack.yaml", ".github/workflows/check.yml", "tests/cases.yaml", "nested/.gitignore", "COM", "LPT", "COM10.txt", "auxiliary.txt", "na\u00efve.txt"} {
		if _, err := safeArchivePath(name); err != nil {
			t.Errorf("rejected portable archive path %q: %v", name, err)
		}
	}
}

func TestExtractRejectsConflictingPathsBeforeWriting(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		paths []string
	}{
		{name: "file ancestor", paths: []string{"policy", "policy/rule.yaml"}},
		{name: "file case alias", paths: []string{"RULE.yaml", "rule.yaml"}},
		{name: "directory case alias", paths: []string{"Tests/fail.yaml", "tests/pass.yaml"}},
		{name: "unicode case alias", paths: []string{"\u03a3.yaml", "\u03c2.yaml"}},
		{name: "unicode normalization alias", paths: []string{"caf\u00e9.yaml", "cafe\u0301.yaml"}},
		{name: "git metadata", paths: []string{"pack.yaml", "nested/.git/config"}},
		{name: "windows stream", paths: []string{"pack.yaml", "tests/file:stream"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			data := archiveWithCanonicalMetadata(t, test.paths)
			target := t.TempDir()
			if _, err := Extract(data, target); err == nil {
				t.Fatal("accepted conflicting archive paths")
			}
			entries, err := os.ReadDir(target)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != 0 {
				t.Fatalf("invalid archive wrote entries before rejection: %v", entries)
			}
		})
	}
}

// Write hostile paths with the same byte format as the producer. Validating
// the metadata alone cannot establish that extraction paths are unambiguous.
func archiveWithCanonicalMetadata(t *testing.T, paths []string) []byte {
	t.Helper()
	paths = append([]string(nil), paths...)
	sort.Strings(paths)
	var data bytes.Buffer
	gz, err := gzip.NewWriterLevel(&data, gzip.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	gz.Header.ModTime = time.Unix(0, 0).UTC()
	gz.Header.OS = 255
	tw := tar.NewWriter(gz)
	for _, name := range paths {
		body := []byte("fixture\n")
		header := &tar.Header{Name: name, Mode: 0o644, Size: int64(len(body)), ModTime: time.Unix(0, 0).UTC(), Typeflag: tar.TypeReg, Format: tar.FormatPAX}
		if err := tw.WriteHeader(header); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	return data.Bytes()
}

func timeNow() time.Time { return time.Now().Add(time.Hour) }
