// Package ocipack contains the only registry and signature command paths used
// for policy packs. Validation and evaluation never import or call it.
package ocipack

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/packarchive"
	"github.com/openhoo/hoolicy/internal/safepath"
)

var digestPattern = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)

const CatalogArtifactType = "application/vnd.openhoo.hoolicy.catalog.v1"
const CatalogMediaType = "application/vnd.openhoo.hoolicy.catalog.v1+json"
const MaxMetadataSize int64 = 2 << 20
const MaxResultsSize int64 = 16 << 20

type Pulled struct {
	Reference       string
	DigestReference string
	ManifestDigest  string
	PackDigest      string
	VerifiedBy      string
	PackRoot        string
	PackName        string
	Release         string
}

type releaseManifest struct {
	Version             int    `json:"version"`
	Pack                string `json:"pack"`
	Release             string `json:"release"`
	Maturity            string `json:"maturity,omitempty"`
	Owner               string `json:"owner,omitempty"`
	CompatibilityNotes  string `json:"compatibilityNotes,omitempty"`
	ArtifactType        string `json:"artifactType"`
	PackMediaType       string `json:"packMediaType"`
	PackDigest          string `json:"packDigest"`
	CompatibilityDigest string `json:"compatibilityDigest"`
	TestResultsDigest   string `json:"testResultsDigest"`
	Provenance          string `json:"provenance"`
}

type manifestExpectation struct {
	artifactType string
	layerTypes   []string
}

var packManifestExpectation = manifestExpectation{artifactType: packarchive.ArtifactType, layerTypes: []string{
	packarchive.MediaType,
	"application/vnd.openhoo.hoolicy.release-manifest.v1+json",
	"application/vnd.openhoo.hoolicy.compatibility.v1+json",
	"application/vnd.openhoo.hoolicy.test-results.v1+json",
}}

var catalogManifestExpectation = manifestExpectation{artifactType: CatalogArtifactType, layerTypes: []string{CatalogMediaType}}

func Pull(projectRoot, reference, trustRelative, target string) (Pulled, error) {
	download, err := os.MkdirTemp("", "hoolicy-oci-pull-*")
	if err != nil {
		return Pulled{}, err
	}
	defer os.RemoveAll(download)
	digest, verifiedBy, err := fetch(projectRoot, reference, trustRelative, download, &packManifestExpectation)
	if err != nil {
		return Pulled{}, err
	}
	digestReference := withDigest(reference, digest)
	data, err := readRegularArtifact(download, "pack.tar.gz", packarchive.MaxArchiveSize)
	if err != nil {
		return Pulled{}, fmt.Errorf("artifact lacks pack.tar.gz: %w", err)
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return Pulled{}, err
	}
	packDigest, err := packarchive.Extract(data, target)
	if err != nil {
		return Pulled{}, fmt.Errorf("extract canonical pack: %w", err)
	}
	manifestData, err := readRegularArtifact(download, "release-manifest.json", MaxMetadataSize)
	if err != nil {
		return Pulled{}, fmt.Errorf("artifact lacks release-manifest.json: %w", err)
	}
	var manifest releaseManifest
	decoder := json.NewDecoder(bytes.NewReader(manifestData))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&manifest); err != nil {
		return Pulled{}, fmt.Errorf("release manifest: %w", err)
	}
	var manifestExtra any
	if err := decoder.Decode(&manifestExtra); err != io.EOF {
		return Pulled{}, errors.New("release manifest must contain exactly one JSON value")
	}
	if manifest.Version != 1 || manifest.ArtifactType != packarchive.ArtifactType || manifest.PackMediaType != packarchive.MediaType || manifest.PackDigest != packDigest || manifest.Pack == "" || manifest.Release == "" || ValidateProvenanceReference(manifest.Provenance) != nil {
		return Pulled{}, errors.New("release manifest does not bind pack identity, release, media type, digest, and provenance")
	}
	pack, err := config.LoadPack(target)
	if err != nil {
		return Pulled{}, fmt.Errorf("extracted pack manifest: %w", err)
	}
	if manifest.Maturity == "" || manifest.Owner == "" || manifest.CompatibilityNotes == "" || pack.Name != manifest.Pack || pack.Release != manifest.Release || pack.Maturity != manifest.Maturity || pack.Owner != manifest.Owner || pack.CompatibilityNotes != manifest.CompatibilityNotes {
		return Pulled{}, errors.New("release manifest does not bind pack maturity, owner, compatibility notes, and extracted manifest")
	}
	for name, expected := range map[string]string{"compatibility.json": manifest.CompatibilityDigest, "test-results.json": manifest.TestResultsDigest} {
		content, err := readRegularArtifact(download, name, MaxResultsSize)
		if err != nil {
			return Pulled{}, fmt.Errorf("artifact lacks %s: %w", name, err)
		}
		hash := sha256.Sum256(content)
		actual := "sha256:" + hex.EncodeToString(hash[:])
		if !digestPattern.MatchString(expected) || actual != expected {
			return Pulled{}, fmt.Errorf("%s digest mismatch", name)
		}
	}
	return Pulled{Reference: reference, DigestReference: digestReference, ManifestDigest: digest, PackDigest: packDigest, VerifiedBy: verifiedBy, PackRoot: target, PackName: manifest.Pack, Release: manifest.Release}, nil
}

// Fetch resolves a mutable reference once, verifies the resulting digest
// against local trust policy, then pulls exactly that verified digest.
func Fetch(projectRoot, reference, trustRelative, target string) (string, string, error) {
	return fetch(projectRoot, reference, trustRelative, target, nil)
}

func FetchCatalog(projectRoot, reference, trustRelative, target string) (string, string, error) {
	return fetch(projectRoot, reference, trustRelative, target, &catalogManifestExpectation)
}

func fetch(projectRoot, reference, trustRelative, target string, expected *manifestExpectation) (string, string, error) {
	digest, err := Resolve(reference)
	if err != nil {
		return "", "", err
	}
	digestReference := withDigest(reference, digest)
	verifiedBy, err := Verify(projectRoot, digestReference, trustRelative)
	if err != nil {
		return "", "", err
	}
	if expected != nil {
		if err := validateRemoteManifest(digestReference, *expected); err != nil {
			return "", "", err
		}
	}
	if err := os.MkdirAll(target, 0o755); err != nil {
		return "", "", err
	}
	command := exec.Command("oras", "pull", "--no-tty", "--output", target, digestReference)
	if output, err := command.CombinedOutput(); err != nil {
		return "", "", fmt.Errorf("oras pull: %s", sanitized(output))
	}
	return digest, verifiedBy, nil
}

func validateRemoteManifest(digestReference string, expected manifestExpectation) error {
	command := exec.Command("oras", "manifest", "fetch", digestReference)
	output, err := command.Output()
	if err != nil {
		message := []byte(nil)
		if exit, ok := err.(*exec.ExitError); ok {
			message = exit.Stderr
		}
		return fmt.Errorf("oras fetch manifest: %s", sanitized(message))
	}
	if len(output) > int(MaxMetadataSize) {
		return fmt.Errorf("OCI manifest exceeds %d bytes", MaxMetadataSize)
	}
	return validateOCIManifest(output, expected)
}

func validateOCIManifest(data []byte, expected manifestExpectation) error {
	var manifest struct {
		SchemaVersion int    `json:"schemaVersion"`
		ArtifactType  string `json:"artifactType"`
		Layers        []struct {
			MediaType string `json:"mediaType"`
		} `json:"layers"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&manifest); err != nil {
		return fmt.Errorf("OCI manifest: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return errors.New("OCI manifest must contain exactly one JSON value")
	}
	if manifest.SchemaVersion != 2 || manifest.ArtifactType != expected.artifactType {
		return fmt.Errorf("OCI manifest artifact type %q does not match required %q", manifest.ArtifactType, expected.artifactType)
	}
	actual := make([]string, 0, len(manifest.Layers))
	for _, layer := range manifest.Layers {
		if layer.MediaType == "" {
			return errors.New("OCI manifest layer lacks media type")
		}
		actual = append(actual, layer.MediaType)
	}
	wanted := append([]string(nil), expected.layerTypes...)
	sort.Strings(actual)
	sort.Strings(wanted)
	left, _ := json.Marshal(actual)
	right, _ := json.Marshal(wanted)
	if !bytes.Equal(left, right) {
		return fmt.Errorf("OCI manifest layer media types %v do not match required %v", actual, wanted)
	}
	return nil
}

func Resolve(reference string) (string, error) {
	if err := config.ValidateOCIReference(reference); err != nil {
		return "", fmt.Errorf("OCI reference: %w", err)
	}
	command := exec.Command("oras", "manifest", "fetch", "--format", "go-template", "--template", "{{ .digest }}", reference)
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("oras resolve: %s", sanitized(output))
	}
	digest := strings.TrimSpace(string(output))
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("oras returned invalid manifest digest %q", digest)
	}
	return digest, nil
}

func Verify(projectRoot, digestReference, trustRelative string) (string, error) {
	if err := config.ValidateOCIReference(digestReference); err != nil {
		return "", fmt.Errorf("OCI digest reference: %w", err)
	}
	_, trustPath, err := safepath.Existing(projectRoot, trustRelative)
	if err != nil {
		return "", fmt.Errorf("trust policy: %w", err)
	}
	trust, err := config.LoadTrust(trustPath)
	if err != nil {
		return "", err
	}
	coordinate := withoutVersion(digestReference)
	matched := false
	var failures []string
	for _, requirement := range trust.Requirements {
		ok, err := path.Match(requirement.Registry, coordinate)
		if err != nil {
			return "", fmt.Errorf("trust requirement %s has invalid registry pattern: %w", requirement.Name, err)
		}
		if !ok {
			continue
		}
		matched = true
		args := []string{"verify", "--output", "json"}
		if requirement.Key != "" {
			_, key, err := safepath.Existing(projectRoot, requirement.Key)
			if err != nil {
				failures = append(failures, requirement.Name+": unsafe key: "+err.Error())
				continue
			}
			args = append(args, "--key", key)
		} else {
			args = append(args, "--certificate-identity", requirement.Identity, "--certificate-oidc-issuer", requirement.Issuer)
		}
		args = append(args, digestReference)
		command := exec.Command("cosign", args...)
		var errorOutput bytes.Buffer
		command.Stderr = &errorOutput
		output, commandErr := command.Output()
		if commandErr != nil {
			failures = append(failures, requirement.Name+": "+sanitized(errorOutput.Bytes()))
			continue
		}
		if !verifiedCosignOutput(output) {
			failures = append(failures, requirement.Name+": no verified signatures")
			continue
		}
		return requirement.Name, nil
	}
	if !matched {
		return "", fmt.Errorf("no trust requirement allows %s", coordinate)
	}
	return "", fmt.Errorf("signature verification failed closed: %s", strings.Join(failures, "; "))
}

func Push(reference, directory, signKey string, keyless bool, annotations map[string]string) (string, error) {
	if (signKey == "") == !keyless {
		return "", errors.New("exactly one signing key or keyless signing is required")
	}
	if err := config.ValidateOCIReference(reference); err != nil {
		return "", fmt.Errorf("OCI reference: %w", err)
	}
	args := []string{"push", "--no-tty", "--artifact-type", packarchive.ArtifactType, "--format", "go-template", "--template", "{{ .digest }}"}
	keys := make([]string, 0, len(annotations))
	for key := range annotations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--annotation", key+"="+annotations[key])
	}
	args = append(args, reference,
		"pack.tar.gz:"+packarchive.MediaType,
		"release-manifest.json:application/vnd.openhoo.hoolicy.release-manifest.v1+json",
		"compatibility.json:application/vnd.openhoo.hoolicy.compatibility.v1+json",
		"test-results.json:application/vnd.openhoo.hoolicy.test-results.v1+json")
	command := exec.Command("oras", args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("oras push: %s", sanitized(output))
	}
	digest := strings.TrimSpace(string(output))
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("oras returned invalid manifest digest %q", digest)
	}
	digestReference := withDigest(reference, digest)
	signArgs := []string{"sign", "--yes"}
	if signKey != "" {
		signArgs = append(signArgs, "--key", signKey)
	}
	signArgs = append(signArgs, digestReference)
	if output, err := exec.Command("cosign", signArgs...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("cosign sign: %s", sanitized(output))
	}
	return digestReference, nil
}

func PushCatalog(reference, directory, signKey string, keyless bool, annotations map[string]string) (string, error) {
	if (signKey == "") == !keyless {
		return "", errors.New("exactly one signing key or keyless signing is required")
	}
	if err := config.ValidateOCIReference(reference); err != nil {
		return "", fmt.Errorf("OCI reference: %w", err)
	}
	args := []string{"push", "--no-tty", "--artifact-type", CatalogArtifactType, "--format", "go-template", "--template", "{{ .digest }}"}
	keys := make([]string, 0, len(annotations))
	for key := range annotations {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		args = append(args, "--annotation", key+"="+annotations[key])
	}
	args = append(args, reference, "catalog.json:"+CatalogMediaType)
	command := exec.Command("oras", args...)
	command.Dir = directory
	output, err := command.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("oras push catalog: %s", sanitized(output))
	}
	digest := strings.TrimSpace(string(output))
	if !digestPattern.MatchString(digest) {
		return "", fmt.Errorf("oras returned invalid manifest digest %q", digest)
	}
	digestReference := withDigest(reference, digest)
	signArgs := []string{"sign", "--yes"}
	if signKey != "" {
		signArgs = append(signArgs, "--key", signKey)
	}
	signArgs = append(signArgs, digestReference)
	if output, err := exec.Command("cosign", signArgs...).CombinedOutput(); err != nil {
		return "", fmt.Errorf("cosign sign catalog: %s", sanitized(output))
	}
	return digestReference, nil
}

func withDigest(reference, digest string) string { return withoutVersion(reference) + "@" + digest }

func withoutVersion(reference string) string {
	lastSlash := strings.LastIndexByte(reference, '/')
	if at := strings.LastIndexByte(reference, '@'); at > lastSlash {
		return reference[:at]
	}
	if colon := strings.LastIndexByte(reference, ':'); colon > lastSlash {
		return reference[:colon]
	}
	return reference
}

func ValidateProvenanceReference(reference string) error {
	if digestPattern.MatchString(reference) {
		return nil
	}
	if err := config.ValidateOCIReference(reference); err == nil && strings.Contains(reference, "@sha256:") {
		return nil
	}
	return errors.New("provenance must be an immutable SHA-256 digest or OCI digest reference")
}

func readRegularArtifact(root, name string, maximum int64) ([]byte, error) {
	_, absolute, err := safepath.Existing(root, name)
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("artifact entry %s is not a regular file", name)
	}
	if info.Size() > maximum {
		return nil, fmt.Errorf("artifact entry %s exceeds %d bytes", name, maximum)
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(opened, info) || opened.Size() > maximum {
		return nil, fmt.Errorf("artifact entry %s changed, is not regular, or exceeds %d bytes", name, maximum)
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maximum || int64(len(data)) != opened.Size() {
		return nil, fmt.Errorf("artifact entry %s changed or exceeds %d bytes", name, maximum)
	}
	return data, nil
}

func verifiedCosignOutput(output []byte) bool {
	var entries []json.RawMessage
	decoder := json.NewDecoder(bytes.NewReader(output))
	if err := decoder.Decode(&entries); err != nil || len(entries) == 0 {
		return false
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return false
	}
	for _, entry := range entries {
		var object map[string]any
		if len(entry) == 0 || json.Unmarshal(entry, &object) != nil || object == nil {
			return false
		}
	}
	return true
}

func sanitized(output []byte) string {
	value := strings.TrimSpace(strings.Map(func(character rune) rune {
		if character == '\n' {
			return character
		}
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, string(output)))
	if value == "" {
		return "command failed"
	}
	lines := strings.Split(value, "\n")
	if len(lines) > 3 {
		lines = lines[len(lines)-3:]
	}
	for index, line := range lines {
		if at := strings.IndexByte(line, '@'); at >= 0 {
			if scheme := strings.LastIndex(line[:at], "://"); scheme >= 0 {
				line = line[:scheme+3] + "<redacted>@" + line[at+1:]
			}
		}
		lines[index] = line
	}
	value = strings.Join(lines, " ")
	runes := []rune(value)
	if len(runes) > 1024 {
		value = string(runes[:1024]) + "..."
	}
	return value
}
