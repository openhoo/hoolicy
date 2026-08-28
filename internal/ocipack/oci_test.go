package ocipack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/packarchive"
)

func TestPullResolvesOnceVerifiesTrustAndChecksBoundDigests(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture uses POSIX shell")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(bin, "oras"), `#!/bin/sh
if [ "$1" = manifest ]; then
  case " $* " in *" go-template "*) printf '%s\n' "$FAKE_MANIFEST_DIGEST";; *) /bin/cat "$FAKE_OCI_MANIFEST";; esac
  exit 0
fi
if [ "$1" = pull ]; then
  case " $* " in *"@${FAKE_MANIFEST_DIGEST} "*) ;; *) echo pull did not use digest >&2; exit 3;; esac
  while [ "$#" -gt 0 ]; do if [ "$1" = --output ]; then shift; out="$1"; fi; shift; done
  /bin/cp "$FAKE_ARTIFACT_DIR"/* "$out"/
  exit 0
fi
exit 2
`)
	writeExecutable(t, filepath.Join(bin, "cosign"), `#!/bin/sh
case " $* " in *" --certificate-identity https://github.com/openhoo/policy/.github/workflows/publish.yml@refs/tags/v1 "*) ;; *) echo wrong identity >&2; exit 1;; esac
case " $* " in *" --certificate-oidc-issuer https://token.actions.githubusercontent.com "*) ;; *) echo wrong issuer >&2; exit 1;; esac
if [ "$FAKE_SIGNATURE" = missing ]; then printf '[]\n'; exit 0; fi
if [ "$FAKE_SIGNATURE" = malformed ]; then printf '[null]\n'; exit 0; fi
printf '[{"verified":true}]\n'
`)
	digest := "sha256:" + strings.Repeat("a", 64)
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_MANIFEST_DIGEST", digest)
	trustPath := filepath.Join(root, ".hoolicy", "trust.yaml")
	writeOCIFile(t, trustPath, `version: 1
requirements:
  - name: official
    registry: ghcr.io/openhoo/*
    identity: https://github.com/openhoo/policy/.github/workflows/publish.yml@refs/tags/v1
    issuer: https://token.actions.githubusercontent.com
`)
	artifact := buildArtifactFixture(t)
	t.Setenv("FAKE_ARTIFACT_DIR", artifact)
	manifestPath := filepath.Join(root, "oci-manifest.json")
	writeOCIFile(t, manifestPath, manifestFixture(packManifestExpectation))
	t.Setenv("FAKE_OCI_MANIFEST", manifestPath)
	pulled, err := Pull(root, "ghcr.io/openhoo/policy:v1", ".hoolicy/trust.yaml", filepath.Join(root, "vendor"))
	if err != nil {
		t.Fatal(err)
	}
	if pulled.ManifestDigest != digest || pulled.VerifiedBy != "official" || pulled.PackDigest == "" {
		t.Fatalf("unexpected pull: %#v", pulled)
	}
	t.Setenv("FAKE_SIGNATURE", "missing")
	if _, err := Pull(root, "ghcr.io/openhoo/policy:v1", ".hoolicy/trust.yaml", filepath.Join(root, "missing")); err == nil || !strings.Contains(err.Error(), "failed closed") {
		t.Fatalf("missing signature accepted: %v", err)
	}
	t.Setenv("FAKE_SIGNATURE", "malformed")
	if _, err := Pull(root, "ghcr.io/openhoo/policy:v1", ".hoolicy/trust.yaml", filepath.Join(root, "malformed")); err == nil || !strings.Contains(err.Error(), "failed closed") {
		t.Fatalf("malformed verification output accepted: %v", err)
	}
	t.Setenv("FAKE_SIGNATURE", "")
	writeOCIFile(t, trustPath, strings.ReplaceAll(mustRead(t, trustPath), "refs/tags/v1", "refs/tags/wrong"))
	if _, err := Pull(root, "ghcr.io/openhoo/policy:v1", ".hoolicy/trust.yaml", filepath.Join(root, "wrong")); err == nil || !strings.Contains(err.Error(), "wrong identity") {
		t.Fatalf("wrong identity accepted: %v", err)
	}
	trustData := strings.ReplaceAll(mustRead(t, trustPath), "refs/tags/wrong", "refs/tags/v1")
	trustData = strings.ReplaceAll(trustData, "https://token.actions.githubusercontent.com", "https://issuer.example.com")
	writeOCIFile(t, trustPath, trustData)
	if _, err := Pull(root, "ghcr.io/openhoo/policy:v1", ".hoolicy/trust.yaml", filepath.Join(root, "issuer")); err == nil || !strings.Contains(err.Error(), "wrong issuer") {
		t.Fatalf("wrong issuer accepted: %v", err)
	}
}

func TestImmutableProvenanceAndRegularArtifactValidation(t *testing.T) {
	t.Parallel()
	for _, valid := range []string{"sha256:" + strings.Repeat("a", 64), "ghcr.io/openhoo/provenance@sha256:" + strings.Repeat("b", 64)} {
		if err := ValidateProvenanceReference(valid); err != nil {
			t.Fatalf("rejected %s: %v", valid, err)
		}
	}
	for _, invalid := range []string{"", "https://example.com/provenance", "ghcr.io/openhoo/provenance:v1"} {
		if err := ValidateProvenanceReference(invalid); err == nil {
			t.Fatalf("accepted mutable provenance %q", invalid)
		}
	}
	root := t.TempDir()
	outside := filepath.Join(t.TempDir(), "outside")
	writeOCIFile(t, outside, "secret")
	if err := os.Symlink(outside, filepath.Join(root, "pack.tar.gz")); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularArtifact(root, "pack.tar.gz", packarchive.MaxArchiveSize); err == nil {
		t.Fatal("followed symbolic artifact file")
	}
}

func TestOCIManifestRequiresExactArtifactAndLayerMediaTypes(t *testing.T) {
	t.Parallel()
	if err := validateOCIManifest([]byte(manifestFixture(packManifestExpectation)), packManifestExpectation); err != nil {
		t.Fatal(err)
	}
	if err := validateOCIManifest([]byte(manifestFixture(catalogManifestExpectation)), catalogManifestExpectation); err != nil {
		t.Fatal(err)
	}
	wrongArtifact := strings.Replace(manifestFixture(packManifestExpectation), packarchive.ArtifactType, CatalogArtifactType, 1)
	if err := validateOCIManifest([]byte(wrongArtifact), packManifestExpectation); err == nil || !strings.Contains(err.Error(), "artifact type") {
		t.Fatalf("wrong artifact type accepted: %v", err)
	}
	wrongLayer := strings.Replace(manifestFixture(packManifestExpectation), packarchive.MediaType, CatalogMediaType, 1)
	if err := validateOCIManifest([]byte(wrongLayer), packManifestExpectation); err == nil || !strings.Contains(err.Error(), "layer media types") {
		t.Fatalf("wrong layer type accepted: %v", err)
	}
}

func TestReadRegularArtifactRejectsOversizedInput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	path := filepath.Join(root, "release-manifest.json")
	writeOCIFile(t, path, "{}")
	if err := os.Truncate(path, MaxMetadataSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := readRegularArtifact(root, "release-manifest.json", MaxMetadataSize); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized artifact accepted: %v", err)
	}
}

func TestPullRejectsReleaseManifestDigestMismatch(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture uses POSIX shell")
	}
	// The full command path is covered above; mutate the signed artifact fixture
	// and reuse it through a permissive key verifier.
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	_ = os.MkdirAll(bin, 0o755)
	writeExecutable(t, filepath.Join(bin, "oras"), `#!/bin/sh
if [ "$1" = manifest ]; then
  case " $* " in *" go-template "*) printf '%s\n' "$FAKE_MANIFEST_DIGEST";; *) /bin/cat "$FAKE_OCI_MANIFEST";; esac
  exit 0
fi
while [ "$#" -gt 0 ]; do if [ "$1" = --output ]; then shift; out="$1"; fi; shift; done
/bin/cp "$FAKE_ARTIFACT_DIR"/* "$out"/
`)
	writeExecutable(t, filepath.Join(bin, "cosign"), "#!/bin/sh\necho '[{}]'\n")
	writeOCIFile(t, filepath.Join(root, "key.pub"), "test")
	writeOCIFile(t, filepath.Join(root, "trust.yaml"), "version: 1\nrequirements:\n  - name: key\n    registry: ghcr.io/openhoo/*\n    key: key.pub\n")
	artifact := buildArtifactFixture(t)
	var manifest map[string]any
	data, _ := os.ReadFile(filepath.Join(artifact, "release-manifest.json"))
	_ = json.Unmarshal(data, &manifest)
	manifest["packDigest"] = "sha256:" + strings.Repeat("f", 64)
	data, _ = json.Marshal(manifest)
	_ = os.WriteFile(filepath.Join(artifact, "release-manifest.json"), data, 0o644)
	t.Setenv("PATH", bin)
	t.Setenv("FAKE_ARTIFACT_DIR", artifact)
	t.Setenv("FAKE_MANIFEST_DIGEST", "sha256:"+strings.Repeat("b", 64))
	manifestPath := filepath.Join(root, "oci-manifest.json")
	writeOCIFile(t, manifestPath, manifestFixture(packManifestExpectation))
	t.Setenv("FAKE_OCI_MANIFEST", manifestPath)
	if _, err := Pull(root, "ghcr.io/openhoo/policy:v1", "trust.yaml", filepath.Join(root, "vendor")); err == nil || !strings.Contains(err.Error(), "does not bind") {
		t.Fatalf("digest mismatch accepted: %v", err)
	}
}

func TestPushCatalogUsesDedicatedMediaTypeAndSignsDigest(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake executable fixture uses POSIX shell")
	}
	root := t.TempDir()
	bin := filepath.Join(root, "bin")
	if err := os.MkdirAll(bin, 0o755); err != nil {
		t.Fatal(err)
	}
	writeExecutable(t, filepath.Join(bin, "oras"), `#!/bin/sh
case " $* " in *" application/vnd.openhoo.hoolicy.catalog.v1 "*" catalog.json:application/vnd.openhoo.hoolicy.catalog.v1+json "*) ;; *) echo wrong catalog media type >&2; exit 2;; esac
echo sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd
`)
	writeExecutable(t, filepath.Join(bin, "cosign"), `#!/bin/sh
case " $* " in *" ghcr.io/openhoo/catalog@sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd "*) exit 0;; *) exit 2;; esac
`)
	t.Setenv("PATH", bin)
	writeOCIFile(t, filepath.Join(root, "catalog.json"), "{}\n")
	result, err := PushCatalog("ghcr.io/openhoo/catalog:v1", root, "", true, map[string]string{"title": "demo"})
	if err != nil || !strings.Contains(result, "@sha256:") {
		t.Fatalf("result=%q err=%v", result, err)
	}
}

func buildArtifactFixture(t *testing.T) string {
	t.Helper()
	pack := t.TempDir()
	writeOCIFile(t, filepath.Join(pack, "pack.yaml"), "version: 1\nname: policy\nrelease: 1.0.0\ndescription: Test policy.\nmaturity: stable\nowner: test-team\ncompatibilityNotes: Stable test fixture.\nrules:\n  - id: policy.required\n    title: Required\n    description: Requires a file.\n    rationale: Tests need a valid pack.\n    remediation: Add REQUIRED.md.\n    severity: error\n    kind: files\n    files: [REQUIRED.md]\n    spec: {mode: require, message: Required}\n")
	archive, digest, err := packarchive.Build(pack)
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	writeOCIBytes(t, filepath.Join(directory, "pack.tar.gz"), archive)
	compatibility := []byte("{}\n")
	tests := []byte("{}\n")
	writeOCIBytes(t, filepath.Join(directory, "compatibility.json"), compatibility)
	writeOCIBytes(t, filepath.Join(directory, "test-results.json"), tests)
	manifest := map[string]any{"version": 1, "pack": "policy", "release": "1.0.0", "maturity": "stable", "owner": "test-team", "compatibilityNotes": "Stable test fixture.", "artifactType": packarchive.ArtifactType, "packMediaType": packarchive.MediaType, "packDigest": digest, "compatibilityDigest": digestBytes(compatibility), "testResultsDigest": digestBytes(tests), "provenance": "sha256:" + strings.Repeat("c", 64)}
	data, _ := json.Marshal(manifest)
	writeOCIBytes(t, filepath.Join(directory, "release-manifest.json"), data)
	return directory
}

func digestBytes(data []byte) string {
	hash := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(hash[:])
}

func manifestFixture(expected manifestExpectation) string {
	layers := make([]map[string]string, 0, len(expected.layerTypes))
	for _, mediaType := range expected.layerTypes {
		layers = append(layers, map[string]string{"mediaType": mediaType, "digest": "sha256:" + strings.Repeat("a", 64), "size": "1"})
	}
	manifest := map[string]any{"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json", "artifactType": expected.artifactType, "layers": layers}
	data, _ := json.Marshal(manifest)
	return string(data)
}
func writeExecutable(t *testing.T, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o755); err != nil {
		t.Fatal(err)
	}
}
func writeOCIFile(t *testing.T, path, data string) { t.Helper(); writeOCIBytes(t, path, []byte(data)) }
func writeOCIBytes(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
func mustRead(t *testing.T, path string) string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}
