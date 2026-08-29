package packarchive

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"fmt"
	"os"
	"path/filepath"
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

func timeNow() time.Time { return time.Now().Add(time.Hour) }
