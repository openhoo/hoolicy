package cli

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/engine"
)

const sourcesProject = `version: 1
project: demo
failOn: error
rules:
  - id: demo.sources
    title: Approved sources
    description: Restricts image registries.
    rationale: Untrusted registries weaken the supply chain.
    remediation: Mirror the image.
    severity: error
    kind: sources.allowed
    files: ['**/*.yml', '**/*.json']
    spec:
      registries: [allowed.example.com]
      message: Unapproved source
`

func checkJSON(t *testing.T, root string, args ...string) (int, engine.Report, string) {
	t.Helper()
	app, stdout, stderr := testApplication(t)
	code := app.run(context.Background(), append([]string{"check", "--config", filepath.Join(root, "hoolicy.yaml"), "--format", "json"}, args...))
	var report engine.Report
	if code != 2 {
		if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
			t.Fatalf("decode report: %v: %s", err, stdout.String())
		}
	}
	return code, report, stderr.String()
}

// Issue #33: duplicate keys in scanned foreign YAML must not abort the rule.
func TestSourcesAllowedScansForeignYAMLWithDuplicateKeysMergesAndCustomTags(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), sourcesProject)
	writeCLIFile(t, filepath.Join(root, ".gitlab-ci.yml"), `include:
  - project: shared/templates
.template: &template
  image: quay.io/template:1
build:
  image: allowed.example.com/build:1
build:
  image: docker.io/override:2
  script: !reference [.setup, script]
inherit:
  <<: *template
override:
  <<: *template
  image: allowed.example.com/explicit:1
`)
	writeCLIFile(t, filepath.Join(root, "images.json"), `{"image":"gcr.io/other:1"}`)
	code, report, stderr := checkJSON(t, root)
	if code != 1 {
		t.Fatalf("duplicate scanned YAML key must not be operational: code=%d stderr=%q", code, stderr)
	}
	var keys []string
	for _, finding := range report.Findings {
		keys = append(keys, finding.Location.Path+" "+finding.Key)
	}
	sort.Strings(keys)
	want := []string{
		".gitlab-ci.yml image:docker.io/override:2",
		".gitlab-ci.yml image:quay.io/template:1",
		".gitlab-ci.yml image:quay.io/template:1#2",
		"images.json image:gcr.io/other:1",
	}
	if strings.Join(keys, "\n") != strings.Join(want, "\n") {
		t.Fatalf("unexpected findings:\n%s", strings.Join(keys, "\n"))
	}
}

func TestSourcesAllowedStillFailsClosedOnMalformedYAML(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), sourcesProject)
	writeCLIFile(t, filepath.Join(root, "broken.yml"), "jobs: [unterminated\n")
	if code, _, stderr := checkJSON(t, root); code != 2 || !strings.Contains(stderr, "broken.yml") {
		t.Fatalf("malformed scanned YAML must remain operational: code=%d stderr=%q", code, stderr)
	}
}

func TestProjectConfigurationStillRejectsDuplicateKeys(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), sourcesProject+"project: shadow\n")
	if code, _, stderr := checkJSON(t, root); code != 2 || !strings.Contains(stderr, "duplicate key") {
		t.Fatalf("policy duplicate key accepted: code=%d stderr=%q", code, stderr)
	}
}

// Repeated identical violations in one document previously shared one
// fingerprint, which broke baseline creation and let one base finding hide
// a newly added duplicate.
func TestRepeatedFindingsGetDistinctFingerprintsForBaselineAndComparison(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), sourcesProject)
	writeCLIFile(t, filepath.Join(root, "ci.yml"), "a:\n  image: docker.io/x:1\n")
	runCLICommand(t, root, "git", "init", "-q", "-b", "main")
	runCLICommand(t, root, "git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "add", ".")
	runCLICommand(t, root, "git", "-c", "user.name=Test", "-c", "user.email=test@example.com", "commit", "-qm", "test: base")
	writeCLIFile(t, filepath.Join(root, "ci.yml"), "a:\n  image: docker.io/x:1\nb:\n  image: docker.io/x:1\n")
	code, report, stderr := checkJSON(t, root, "--base", "HEAD")
	if code != 1 || report.Summary.New != 1 || report.Summary.Existing != 1 {
		t.Fatalf("added duplicate violation hidden by base finding: code=%d summary=%+v stderr=%q", code, report.Summary, stderr)
	}
	if report.Findings[0].Fingerprint == report.Findings[1].Fingerprint {
		t.Fatal("repeated findings share a fingerprint")
	}
	app, stdout, stderr2 := testApplication(t)
	if code := app.run(context.Background(), []string{"baseline", "create", "--config", filepath.Join(root, "hoolicy.yaml"), "--apply"}); code != 0 {
		t.Fatalf("baseline create failed: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr2.String())
	}
	code, report, stderr = checkJSON(t, root)
	if code != 0 || report.Summary.Existing != 2 || report.Summary.Blocking != 0 {
		t.Fatalf("baseline did not accept both reviewed findings: code=%d summary=%+v stderr=%q", code, report.Summary, stderr)
	}
}

const celProject = `version: 1
project: demo
failOn: error
rules:
  - id: demo.cel
    title: CEL violations
    description: Returns violation objects.
    rationale: Structured rules need precise locations.
    remediation: Correct the document.
    severity: error
    kind: structured.cel
    files: [config.json]
    spec:
      format: json
      expression: %s
      message: Fallback message
`

func TestStructuredCELViolationListThroughEngine(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), strings.Replace(celProject, "%s",
		`"documents.map(d, {'message': 'Replica count too low', 'path': d.path, 'key': 'replicas', 'line': 2, 'column': 5}) + [{'index': 7}]"`, 1))
	writeCLIFile(t, filepath.Join(root, "config.json"), `{"replicas":1}`)
	code, report, stderr := checkJSON(t, root)
	if code != 1 || len(report.Findings) != 2 {
		t.Fatalf("code=%d findings=%+v stderr=%q", code, report.Findings, stderr)
	}
	var located, fallback bool
	for _, finding := range report.Findings {
		switch {
		case finding.Message == "Replica count too low" && finding.Location.Path == "config.json" && finding.Key == "replicas" && finding.Location.Line == 2 && finding.Location.Column == 5:
			located = true
		case finding.Message == "Fallback message" && finding.Location.Path == "" && finding.Key == "cel:1":
			fallback = true
		}
	}
	if !located || !fallback {
		t.Fatalf("violation fields not preserved: %+v", report.Findings)
	}
}

func TestStructuredCELRejectsMalformedViolations(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct{ expression, want string }{
		"non-object":     {`"[1]"`, "must be an object"},
		"non-string key": {`"[{1: 'x'}]"`, "non-string key"},
		"message type":   {`"[{'message': 1}]"`, "message must be a string"},
		"line type":      {`"[{'line': 'two'}]"`, "line"},
		"negative line":  {`"[{'line': -1}]"`, "non-negative"},
		"unsafe path":    {`"[{'path': '../outside'}]"`, "safe repository-relative path"},
		"wrong result":   {`"'text'"`, "bool or list"},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), strings.Replace(celProject, "%s", test.expression, 1))
			writeCLIFile(t, filepath.Join(root, "config.json"), `{}`)
			if code, _, stderr := checkJSON(t, root); code != 2 || !strings.Contains(stderr, test.want) {
				t.Fatalf("code=%d stderr=%q, want %q", code, stderr, test.want)
			}
		})
	}
}

func TestStructuredCELViolationListKeepsCostLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	project := strings.Replace(celProject, "%s", `"[1,2,3,4,5,6,7,8,9,10].map(a, [1,2,3,4,5,6,7,8,9,10].map(b, {'key': string(a) + string(b)}))[0]"`, 1)
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), strings.Replace(project, "      message: Fallback message\n", "      message: Fallback message\n      costLimit: 50\n", 1))
	writeCLIFile(t, filepath.Join(root, "config.json"), `{}`)
	if code, _, stderr := checkJSON(t, root); code != 2 || !strings.Contains(stderr, "cost limit") {
		t.Fatalf("cost limit not enforced: code=%d stderr=%q", code, stderr)
	}
}

func TestLintCountsCELPackParameterReadsAsUsed(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	manifest := `version: 1
name: limits
release: 0.1.0
description: Reads parameters inside CEL.
maturity: experimental
owner: openhoo/hoolicy-maintainers
compatibility: {config: '>=1 <2', hoolicy: '>=0.0.0 <2.0.0'}
parameters:
  minimum_replicas: {type: number, default: 2, description: Replica floor read through pack.}
%s
rules:
  - id: limits.replicas
    title: Replica floor
    description: Reads the replica floor through the pack variable.
    rationale: Production services need redundancy.
    remediation: Raise replicas to at least the configured floor.
    severity: error
    kind: structured.cel
    files: [deploy.json]
    spec:
      format: json
      expression: documents.all(d, d.data.replicas >= pack.minimum_replicas)
      message: Replica floor violated
`
	writeCLIFile(t, filepath.Join(root, "clean", "pack.yaml"), strings.Replace(manifest, "%s\n", "", 1))
	writeCLIFile(t, filepath.Join(root, "unread", "pack.yaml"), strings.Replace(manifest, "%s", "  maximum_timeout_ms: {type: number, default: 30000, description: Declared but never read.}", 1))
	app, stdout, stderr := testApplication(t)
	if code := app.run(context.Background(), []string{"lint", "--format", "json", filepath.Join(root, "clean")}); code != 0 || strings.Contains(stdout.String(), "unused-parameter") {
		t.Fatalf("pack.x read reported unused: code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	stderr.Reset()
	app.run(context.Background(), []string{"lint", "--format", "json", filepath.Join(root, "unread")})
	if !strings.Contains(stdout.String(), "parameter:maximum_timeout_ms") || strings.Contains(stdout.String(), "parameter:minimum_replicas") {
		t.Fatalf("unexpected unused-parameter findings: stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
}

func TestStructuredCELExtensionsFlattenFindingsWithinCostLimit(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), strings.Replace(celProject, "%s",
		`"documents.map(d, d.data.services.transformList(name, service, service.replicas < 2 ? [{'message': [name, 'needs', 'replicas'].join(' '), 'path': d.path, 'key': name}] : [])).flatten(2)"`, 1))
	writeCLIFile(t, filepath.Join(root, "config.json"), `{"services":{"api":{"replicas":1},"web":{"replicas":3},"worker":{"replicas":0}}}`)
	code, report, stderr := checkJSON(t, root)
	if code != 1 || len(report.Findings) != 2 {
		t.Fatalf("code=%d findings=%+v stderr=%q", code, report.Findings, stderr)
	}
	messages := []string{report.Findings[0].Message, report.Findings[1].Message}
	sort.Strings(messages)
	if messages[0] != "api needs replicas" || messages[1] != "worker needs replicas" {
		t.Fatalf("unexpected per-occurrence findings: %v", messages)
	}
}

func TestStructuredCELExtensionCostLimitIsOperationalError(t *testing.T) {
	t.Parallel()
	var nested, words strings.Builder
	nested.WriteString(`{"nested":[`)
	words.WriteString(`"words":[`)
	for index := range 60000 {
		if index > 0 {
			nested.WriteByte(',')
			words.WriteByte(',')
		}
		nested.WriteString("[1]")
		words.WriteString(`"word"`)
	}
	data := nested.String() + "]," + words.String() + "]}"
	for name, expression := range map[string]string{
		"flatten": `"documents[0].data.nested.flatten().size() > 0"`,
		"join":    `"documents[0].data.words.join(',').size() > 0"`,
		"range":   `"lists.range(100000).map(i, [i]).flatten().size() > 0"`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root := t.TempDir()
			project := strings.Replace(celProject, "%s", expression, 1)
			writeCLIFile(t, filepath.Join(root, "hoolicy.yaml"), strings.Replace(project, "      message: Fallback message\n", "      message: Fallback message\n      costLimit: 50000\n", 1))
			writeCLIFile(t, filepath.Join(root, "config.json"), data)
			if code, _, stderr := checkJSON(t, root); code != 2 || !strings.Contains(stderr, "cost limit exceeded") {
				t.Fatalf("extension cost not bounded: code=%d stderr=%q", code, stderr)
			}
		})
	}
}
