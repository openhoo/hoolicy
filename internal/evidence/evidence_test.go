package evidence_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/config"
	"github.com/openhoo/hoolicy/internal/engine"
	"github.com/openhoo/hoolicy/internal/evidence"
	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestBundleBuildAndVerificationBindEveryInput(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	subject := "sha256:" + strings.Repeat("a", 64)
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	bom := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-28T11:30:00Z","component":{"hashes":[{"alg":"SHA-256","content":"` + strings.TrimPrefix(subject, "sha256:") + `"}]}},"components":[{"name":"demo"}]}` + "\n")
	writeEvidenceFile(t, filepath.Join(root, "evidence", "bom.json"), bom)
	writeEvidenceFile(t, filepath.Join(root, config.DefaultEvidence), []byte("version: 1\nexternal:\n  - id: sbom\n    type: cyclonedx\n    path: evidence/bom.json\n    sha256: "+sha(bom)+"\n    subjectDigest: "+subject+"\n    maximumAge: 2h\n    minimumItems: 1\n"))
	writeEvidenceFile(t, filepath.Join(root, config.DefaultFilename), []byte(`version: 1
project: demo
rules:
  - id: demo.readme
    title: README
    description: Requires README.
    rationale: Contributors need context.
    remediation: Add a reviewed README file.
    severity: error
    kind: files
    files: [README.md]
    controls: [{framework: demo, id: DOC-1}]
    spec: {mode: require, message: README missing}
`))
	writeEvidenceFile(t, filepath.Join(root, "README.md"), []byte("ok\n"))
	project, err := config.LoadProject(filepath.Join(root, config.DefaultFilename))
	if err != nil {
		t.Fatal(err)
	}
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	checker := engine.New(registry)
	git := sdk.GitContext{Commit: strings.Repeat("b", 40), Properties: map[string]any{}}
	ruleSet, err := checker.Validate(project)
	if err != nil {
		t.Fatal(err)
	}
	decision, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "0.5.0", GitContext: &git})
	if err != nil {
		t.Fatal(err)
	}
	bundle, err := evidence.Build(project, decision, ruleSet)
	if err != nil {
		t.Fatal(err)
	}
	if len(bundle.External) != 1 || bundle.External[0].Metrics["items"] != 1 || len(bundle.Controls) != 1 || bundle.Controls[0].Status != "passed" {
		t.Fatalf("unexpected bundle: %#v", bundle)
	}
	data, err := evidence.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	bundlePath := filepath.Join(root, "bundle.json")
	writeEvidenceFile(t, bundlePath, data)
	var nullBundle map[string]any
	if err := json.Unmarshal(data, &nullBundle); err != nil {
		t.Fatal(err)
	}
	nullBundle["rules"] = nil
	nullRules, err := json.Marshal(nullBundle)
	if err != nil {
		t.Fatal(err)
	}
	writeEvidenceFile(t, filepath.Join(root, "null-rules.json"), nullRules)
	if _, err := evidence.Load(filepath.Join(root, "null-rules.json")); err == nil {
		t.Fatal("null evidence rules accepted")
	}
	wrongRevision := strings.Replace(string(data), strings.Repeat("b", 40), "not-a-git-revision", 1)
	writeEvidenceFile(t, filepath.Join(root, "wrong-revision.json"), []byte(wrongRevision))
	if _, err := evidence.Load(filepath.Join(root, "wrong-revision.json")); err == nil {
		t.Fatal("invalid evidence revision accepted")
	}
	loaded, err := evidence.Load(bundlePath)
	if err != nil {
		t.Fatal(err)
	}
	current, err := checker.Check(context.Background(), project, engine.Options{Now: now, ToolVersion: "0.5.0", GitContext: &git})
	if err != nil {
		t.Fatal(err)
	}
	if err := evidence.Verify(project, loaded, current, ruleSet, now); err != nil {
		t.Fatal(err)
	}
	storedFindings := loaded.Decision.Findings
	currentFindings := current.Findings
	invalidFinding := sdk.Finding{
		RuleID: "demo.readme", Title: "README", Message: "invalid property", Remediation: "Add a reviewed README file.", Severity: sdk.SeverityError,
		Fingerprint: strings.Repeat("c", 64), PolicyDigest: "sha256:" + strings.Repeat("d", 64), FindingDigest: "sha256:" + strings.Repeat("e", 64), State: sdk.FindingNew,
		Properties: map[string]any{"channel": make(chan struct{})},
	}
	loaded.Decision.Findings = []sdk.Finding{invalidFinding}
	current.Findings = []sdk.Finding{invalidFinding}
	if err := evidence.Verify(project, loaded, current, ruleSet, now); err == nil || !strings.Contains(err.Error(), "encode JSON comparison") {
		t.Fatalf("unencodable decision comparison accepted: %v", err)
	}
	loaded.Decision.Findings = storedFindings
	current.Findings = currentFindings
	loaded.Tool.Version = "forged"
	if err := evidence.Verify(project, loaded, current, ruleSet, now); err == nil || !strings.Contains(err.Error(), "envelope") {
		t.Fatalf("forged tool envelope accepted: %v", err)
	}
	loaded.Tool.Version = "0.5.0"
	loaded.External[0].Metrics["items"] = 99
	if err := evidence.Verify(project, loaded, current, ruleSet, now); err == nil || !strings.Contains(err.Error(), "changed") {
		t.Fatalf("forged external metrics accepted: %v", err)
	}
	loaded.External[0].Metrics["items"] = 1
	writeEvidenceFile(t, filepath.Join(root, "evidence", "bom.json"), append(bom, ' '))
	if err := evidence.Verify(project, loaded, current, ruleSet, now); err == nil || !strings.Contains(err.Error(), "digest mismatch") {
		t.Fatalf("mutated external evidence accepted: %v", err)
	}
}

func TestExternalEvidenceFailsClosedOnSubjectFreshnessAndThreshold(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	subject := "sha256:" + strings.Repeat("c", 64)
	sarif := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"results":[{"message":{"text":"failure"}}],"properties":{"hoolicy.subjectDigest":"` + subject + `","hoolicy.generatedAt":"2026-08-20T00:00:00Z"}}]}`)
	writeEvidenceFile(t, filepath.Join(root, "result.sarif"), sarif)
	spec := evidence.ExternalSpec{ID: "scan", Type: "sarif", Path: "result.sarif", SHA256: sha(sarif), SubjectDigest: subject, MaximumAge: "1h", MaximumFailures: 0}
	if _, err := evidence.InspectExternal(root, spec, time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "stale") {
		t.Fatalf("stale evidence accepted: %v", err)
	}
	spec.MaximumAge = ""
	if _, err := evidence.InspectExternal(root, spec, time.Date(2026, 8, 28, 0, 0, 0, 0, time.UTC)); err == nil || !strings.Contains(err.Error(), "failures") {
		t.Fatalf("failed SARIF accepted: %v", err)
	}
	missing := []byte(`{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"results":[],"properties":{"note":"` + subject + `"}}]}`)
	writeEvidenceFile(t, filepath.Join(root, "result.sarif"), missing)
	spec.SHA256 = sha(missing)
	if _, err := evidence.InspectExternal(root, spec, time.Now()); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("missing subject accepted: %v", err)
	}
}

func TestEvidenceLoadRejectsOversizedInputBeforeParsing(t *testing.T) {
	t.Parallel()
	path := filepath.Join(t.TempDir(), "oversized.json")
	writeEvidenceFile(t, path, []byte("{}"))
	if err := os.Truncate(path, evidence.MaxEvidenceFileSize+1); err != nil {
		t.Fatal(err)
	}
	if _, err := evidence.Load(path); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized evidence accepted: %v", err)
	}
}

func TestExternalAdaptersRequireSchemaAndDefinedSubjectBinding(t *testing.T) {
	t.Parallel()
	subject := "sha256:" + strings.Repeat("d", 64)
	hexSubject := strings.TrimPrefix(subject, "sha256:")
	now := time.Date(2026, 8, 28, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name, kind, producer, body string
		items                      int
	}{
		{"sarif", "sarif", "scanner", `{"version":"2.1.0","runs":[{"tool":{"driver":{"name":"scanner"}},"invocations":[{"endTimeUtc":"2026-08-28T11:30:00Z"}],"results":[],"properties":{"hoolicy.subjectDigest":"` + subject + `"}}]}`, 0},
		{"cyclonedx", "cyclonedx", "syft", `{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-28T11:30:00Z","tools":[{"name":"syft"}],"component":{"hashes":[{"alg":"SHA-256","content":"` + hexSubject + `"}]}},"components":[{"name":"demo"}]}`, 1},
		{"spdx", "spdx", "syft", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/demo","creationInfo":{"created":"2026-08-28T11:30:00Z","creators":["Tool: syft-1.0"]},"documentDescribes":["SPDXRef-Package"],"packages":[{"SPDXID":"SPDXRef-Package","name":"demo","checksums":[{"algorithm":"SHA256","checksumValue":"` + hexSubject + `"}]}]}`, 1},
		{"spdx-relationship", "spdx", "syft", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/demo","creationInfo":{"created":"2026-08-28T11:30:00Z","creators":["Tool: syft-1.0"]},"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-Package"}],"packages":[{"SPDXID":"SPDXRef-Package","name":"demo","checksums":[{"algorithm":"SHA256","checksumValue":"` + hexSubject + `"}]}]}`, 1},
		{"spdx-file", "spdx", "syft", `{"spdxVersion":"SPDX-2.3","SPDXID":"SPDXRef-DOCUMENT","name":"demo","dataLicense":"CC0-1.0","documentNamespace":"https://example.invalid/spdx/file","creationInfo":{"created":"2026-08-28T11:30:00Z","creators":["Tool: syft-1.0"]},"relationships":[{"spdxElementId":"SPDXRef-DOCUMENT","relationshipType":"DESCRIBES","relatedSpdxElement":"SPDXRef-File"}],"files":[{"SPDXID":"SPDXRef-File","fileName":"demo","checksums":[{"algorithm":"SHA256","checksumValue":"` + hexSubject + `"}]}]}`, 1},
		{"provenance", "provenance", "https://builder.example", `{"_type":"https://in-toto.io/Statement/v1","subject":[{"name":"artifact","digest":{"sha256":"` + hexSubject + `"}}],"predicateType":"https://slsa.dev/provenance/v1","predicate":{"builder":{"id":"https://builder.example"},"metadata":{"buildFinishedOn":"2026-08-28T11:30:00Z"}}}`, 1},
		{"junit", "junit", "runner", `<testsuites tests="1" failures="0" timestamp="2026-08-28T11:30:00Z"><properties><property name="hoolicy.subjectDigest" value="` + subject + `"/><property name="hoolicy.producer" value="runner"/></properties><testsuite tests="1" failures="0"/></testsuites>`, 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(test.body)
			spec := evidence.ExternalSpec{ID: test.name, Type: test.kind, Path: test.name, SHA256: sha(data), SubjectDigest: subject, RequiredProducer: test.producer, MaximumAge: "1h", MinimumItems: test.items}
			record, err := evidence.InspectExternalBytes(spec, data, now)
			if err != nil || !record.Verified || record.Metrics["items"] != test.items {
				t.Fatalf("record=%#v err=%v", record, err)
			}
		})
	}

	unbound := []byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","metadata":{"timestamp":"2026-08-28T11:30:00Z","tools":[{"name":"syft"}],"component":{"hashes":[{"alg":"SHA-256","content":"` + strings.Repeat("e", 64) + `"}]},"note":"` + subject + `"},"components":[]}`)
	spec := evidence.ExternalSpec{ID: "unbound", Type: "cyclonedx", SHA256: sha(unbound), SubjectDigest: subject, RequiredProducer: "syft"}
	if _, err := evidence.InspectExternalBytes(spec, unbound, now); err == nil || !strings.Contains(err.Error(), "subject") {
		t.Fatalf("unbound subject text accepted: %v", err)
	}
	sarif := []byte(tests[0].body)
	invalidAge := evidence.ExternalSpec{ID: "invalid-age", Type: "sarif", SHA256: sha(sarif), SubjectDigest: subject, RequiredProducer: "scanner", MaximumAge: "not-a-duration"}
	if _, err := evidence.InspectExternalBytes(invalidAge, sarif, now); err == nil || !strings.Contains(err.Error(), "maximumAge") {
		t.Fatalf("invalid maximumAge accepted: %v", err)
	}
}

func sha(data []byte) string {
	sum := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func writeEvidenceFile(t *testing.T, path string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
}
