package main

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// Exercise the installer with real archive/checksum bytes and local download
// fixtures. Signature verification is stubbed; these tests cover the installer's
// checks after verification, without requiring network access or credentials.
func TestSetupInstallerValidatesExactVersionAndCleansTemporaryFiles(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix executable archive fixture")
	}
	for _, tc := range []struct {
		name, requested, reported string
		wantOK                    bool
	}{
		{"exact", "0.4.1", "0.4.1", true},
		{"prefix collision", "0.4.1", "0.4.10", false},
		{"prerelease mismatch", "0.4.1", "0.4.1-rc.1", false},
		{"full semver", "1.2.3-rc.1+build.01", "1.2.3-rc.1+build.01", true},
		{"build hyphen", "1.2.3+build-01", "1.2.3+build-01", true},
		{"numeric prerelease", "1.2.3-01", "1.2.3-01", false},
		{"empty prerelease identifier", "1.2.3-rc..1", "1.2.3-rc..1", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			fixtures := filepath.Join(root, "fixtures")
			mockBin := filepath.Join(root, "mock bin")
			runnerTemp := filepath.Join(root, "runner temp")
			for _, dir := range []string{fixtures, mockBin, runnerTemp} {
				if err := os.Mkdir(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			archiveName := fmt.Sprintf("hoolicy_%s_linux_amd64.tar.gz", tc.requested)
			archive := filepath.Join(fixtures, archiveName)
			makeInstallerArchive(t, archive, tc.reported)
			raw, err := os.ReadFile(archive)
			if err != nil {
				t.Fatal(err)
			}
			writeExecutableFixture(t, filepath.Join(fixtures, "SHA256SUMS"), fmt.Sprintf("%x  %s\n", sha256.Sum256(raw), archiveName))
			for _, name := range []string{archiveName + ".sigstore.json", "SHA256SUMS.sigstore.json"} {
				writeExecutableFixture(t, filepath.Join(fixtures, name), "{}")
			}
			writeExecutableFixture(t, filepath.Join(mockBin, "curl"), `#!/usr/bin/env bash
set -euo pipefail
output=""
url=""
while (( $# )); do
  case "$1" in
    --output) output="$2"; shift 2 ;;
    --retry|--connect-timeout) shift 2 ;;
    --*) shift ;;
    *) url="$1"; shift ;;
  esac
done
cp "$INSTALL_FIXTURES/${url##*/}" "$output"
`)
			writeExecutableFixture(t, filepath.Join(mockBin, "cosign"), "#!/usr/bin/env bash\nexit 0\n")
			pathFile, outputFile := filepath.Join(root, "github-path"), filepath.Join(root, "github-output")
			command := exec.Command("bash", "../actions/setup/install.sh")
			command.Env = append(os.Environ(), "PATH="+mockBin+string(os.PathListSeparator)+os.Getenv("PATH"),
				"INSTALL_FIXTURES="+fixtures, "RUNNER_TEMP="+runnerTemp, "HOOLICY_VERSION="+tc.requested,
				"RUNNER_OS_VALUE=Linux", "RUNNER_ARCH_VALUE=X64", "GITHUB_PATH="+pathFile, "GITHUB_OUTPUT="+outputFile)
			output, err := command.CombinedOutput()
			if (err == nil) != tc.wantOK {
				t.Fatalf("installer error = %v, want success %v:\n%s", err, tc.wantOK, output)
			}
			entries, err := os.ReadDir(runnerTemp)
			if err != nil {
				t.Fatal(err)
			}
			if tc.wantOK {
				if len(entries) != 1 || !strings.HasPrefix(entries[0].Name(), "hoolicy-bin.") {
					t.Fatalf("only installed binary directory should remain: %v", entries)
				}
				pathRaw, err := os.ReadFile(pathFile)
				if err != nil || strings.TrimSpace(string(pathRaw)) != filepath.Join(runnerTemp, entries[0].Name()) {
					t.Fatalf("incorrect PATH publication: %q, %v", pathRaw, err)
				}
			} else {
				if len(entries) != 0 {
					t.Fatalf("failed install left temporary files: %v", entries)
				}
				if _, err := os.Stat(pathFile); !os.IsNotExist(err) {
					t.Fatalf("failed install published PATH: %v", err)
				}
			}
		})
	}
}

func writeExecutableFixture(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
		t.Fatal(err)
	}
}

func makeInstallerArchive(t *testing.T, path, version string) {
	t.Helper()
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	gzipWriter := gzip.NewWriter(file)
	tarWriter := tar.NewWriter(gzipWriter)
	script := "#!/usr/bin/env bash\nprintf '%s\\n' 'hoolicy " + version + " (commit fixture, built fixture)'\n"
	if err := tarWriter.WriteHeader(&tar.Header{Name: "release/hoolicy", Mode: 0o755, Size: int64(len(script))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tarWriter.Write([]byte(script)); err != nil {
		t.Fatal(err)
	}
	for _, closer := range []interface{ Close() error }{tarWriter, gzipWriter, file} {
		if err := closer.Close(); err != nil {
			t.Fatal(err)
		}
	}
}
