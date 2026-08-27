package rules

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestGenericRuleKinds(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "README.md", "hello\nforbidden token\n")
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	input := sdk.EvalContext{Repository: repo, Now: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)}

	missing := baseRule("demo.license", "files", []string{"LICENSE"}, map[string]any{
		"mode": "require", "message": "License missing",
		"create": map[string]any{"path": "LICENSE", "content": "license\n"},
	})
	findings, err := (Files{}).Evaluate(context.Background(), input, missing)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Fix == nil || findings[0].Fix.Edits[0].ExpectedSHA256 != "missing" {
		t.Fatalf("unexpected file finding: %#v", findings)
	}

	textRule := baseRule("demo.text", "text", []string{"**/*.md"}, map[string]any{
		"require": []any{"hello"}, "forbid": []any{"forbidden"}, "message": "Text failed",
	})
	findings, err = (Text{}).Evaluate(context.Background(), input, textRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Location.Line != 2 {
		t.Fatalf("unexpected text findings: %#v", findings)
	}
}

func TestRuleValidationRejectsDisabledNumericConstraints(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		kind sdk.RuleKind
		rule sdk.Rule
	}{
		{name: "negative file minimum", kind: Files{}, rule: baseRule("demo.files", "files", []string{"*.txt"}, map[string]any{"mode": "count", "minimum": -1})},
		{name: "inverted file range", kind: Files{}, rule: baseRule("demo.files", "files", []string{"*.txt"}, map[string]any{"mode": "count", "minimum": 3, "maximum": 2})},
		{name: "ignored file maximum", kind: Files{}, rule: baseRule("demo.files", "files", []string{"*.txt"}, map[string]any{"mode": "require", "maximum": 2})},
		{name: "invalid file glob", kind: Files{}, rule: baseRule("demo.files", "files", []string{"[broken"}, map[string]any{"mode": "require"})},
		{name: "unrelated create path", kind: Files{}, rule: baseRule("demo.files", "files", []string{"README.md"}, map[string]any{"mode": "require", "create": map[string]any{"path": "SECURITY.md", "content": "unsafe"}})},
		{name: "traversing create path", kind: Files{}, rule: baseRule("demo.files", "files", []string{"**/*"}, map[string]any{"mode": "require", "create": map[string]any{"path": "../outside", "content": "unsafe"}})},
		{name: "negative title maximum", kind: GitNaming{}, rule: baseRule("demo.git", "git.naming", nil, map[string]any{"mergeRequestTitleMaximum": -1})},
		{name: "orphan branch allowlist", kind: GitNaming{}, rule: baseRule("demo.git", "git.naming", nil, map[string]any{"commitPattern": ".+", "allowedBranches": []any{"main"}})},
		{name: "negative scenarios", kind: GherkinRequirements{}, rule: baseRule("demo.gherkin", "gherkin.requirements", []string{"*.feature"}, map[string]any{"minimumScenarios": -1})},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.kind.Validate(test.rule); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestCELProgramCacheConcurrent(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "source.json", "{\"enabled\": true}\n")
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("concurrent.cel", "structured.cel", []string{"source.json"}, map[string]any{
		"expression": "documents.all(d, d.data.enabled == true)", "message": "enabled must be true",
	})
	input := sdk.EvalContext{Repository: repo, Now: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)}
	const workers = 32
	errors := make(chan error, workers)
	var group sync.WaitGroup
	for range workers {
		group.Add(1)
		go func() {
			defer group.Done()
			if err := kind.Validate(rule); err != nil {
				errors <- err
				return
			}
			findings, err := kind.Evaluate(context.Background(), input, rule)
			if err != nil {
				errors <- err
				return
			}
			if len(findings) != 0 {
				errors <- fmt.Errorf("unexpected findings: %#v", findings)
			}
		}()
	}
	group.Wait()
	close(errors)
	for err := range errors {
		t.Error(err)
	}
	kind.compiler.mu.Lock()
	defer kind.compiler.mu.Unlock()
	if len(kind.compiler.programs) != 1 {
		t.Fatalf("expected one cached CEL program, got %d", len(kind.compiler.programs))
	}
}

func TestCELAndManifestConsistency(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "source.json", "{\"version\": 2, \"enabled\": false}\n")
	writeRuleFile(t, root, "target.json", "{\"version\": 1}\n")
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	input := sdk.EvalContext{Repository: repo, Now: time.Now().UTC()}

	celRule := baseRule("demo.cel", "structured.cel", []string{"source.json"}, map[string]any{
		"expression": "documents.all(d, d.data.enabled == true)", "message": "enabled must be true",
	})
	celKind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	if err := celKind.Validate(celRule); err != nil {
		t.Fatal(err)
	}
	if len(celKind.compiler.programs) != 1 {
		t.Fatalf("expected one cached CEL program, got %d", len(celKind.compiler.programs))
	}
	findings, err := celKind.Evaluate(context.Background(), input, celRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(celKind.compiler.programs) != 1 {
		t.Fatalf("CEL evaluation recompiled program, cache has %d entries", len(celKind.compiler.programs))
	}
	if len(findings) != 1 || findings[0].Message != "enabled must be true" {
		t.Fatalf("unexpected CEL findings: %#v", findings)
	}
	tooExpensive := celRule
	tooExpensive.Spec = cloneMap(celRule.Spec)
	tooExpensive.Spec["costLimit"] = 1_000_001
	if err := (CEL{}).Validate(tooExpensive); err == nil {
		t.Fatal("expected cost limit validation error")
	}

	manifestRule := baseRule("demo.manifest", "manifest.consistency", nil, map[string]any{
		"authoritative": map[string]any{"path": "source.json", "pointer": "/version"},
		"targets":       []any{map[string]any{"path": "target.json", "pointer": "/version"}},
		"message":       "Versions differ",
	})
	findings, err = (ManifestConsistency{}).Evaluate(context.Background(), input, manifestRule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Fix == nil || string(findings[0].Fix.Edits[0].Replacement) != "2" {
		t.Fatalf("unexpected manifest finding: %#v", findings)
	}
}

func TestManifestConsistencyPreservesValueTypes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "source.json", `{"version": 1}`)
	writeRuleFile(t, root, "target.json", `{"version": "1"}`)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.manifest", "manifest.consistency", nil, map[string]any{
		"authoritative": map[string]any{"path": "source.json", "pointer": "/version"},
		"targets":       []any{map[string]any{"path": "target.json", "pointer": "/version"}},
		"message":       "Versions differ",
	})
	findings, err := (ManifestConsistency{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Fix == nil || string(findings[0].Fix.Edits[0].Replacement) != "1" {
		t.Fatalf("typed mismatch was not reported correctly: %#v", findings)
	}
	writeRuleFile(t, root, "source.json", `{"version": 9223372036854775808}`)
	writeRuleFile(t, root, "target.json", `{"version": "9223372036854775808"}`)
	repo, err = repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	findings, err = (ManifestConsistency{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].Fix == nil || string(findings[0].Fix.Edits[0].Replacement) != "9223372036854775808" {
		t.Fatalf("large typed mismatch was not reported correctly: %#v", findings)
	}
}

func BenchmarkCELValidateAndEvaluate(b *testing.B) {
	root := b.TempDir()
	writeRuleFile(b, root, "source.json", "{\"version\": 2, \"enabled\": true}\n")
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		b.Fatal(err)
	}
	input := sdk.EvalContext{Repository: repo, Now: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)}
	rule := baseRule("bench.cel", "structured.cel", []string{"source.json"}, map[string]any{
		"expression": "documents.all(d, d.data.enabled == true)", "message": "enabled must be true",
	})
	cached, err := newCEL()
	if err != nil {
		b.Fatal(err)
	}
	benchmarks := []struct {
		name string
		kind CEL
	}{
		{name: "cached", kind: cached},
		{name: "uncached", kind: CEL{}},
	}
	for _, benchmark := range benchmarks {
		b.Run(benchmark.name, func(b *testing.B) {
			b.ReportAllocs()
			for range b.N {
				if err := benchmark.kind.Validate(rule); err != nil {
					b.Fatal(err)
				}
				if _, err := benchmark.kind.Evaluate(context.Background(), input, rule); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func TestSourceAndExceptionRules(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "Dockerfile", "FROM evil.example/app:latest AS build\nFROM build AS final\n")
	writeRuleFile(t, root, ".trivyignore.yaml", `vulnerabilities:
  - id: CVE-1
    statement: too short
    owner: security@example.com
    ticket: HTTP://invalid
    created_at: 2026-01-01
    expired_at: 2027-01-01
`)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	input := sdk.EvalContext{Repository: repo, Now: time.Date(2026, 8, 26, 0, 0, 0, 0, time.UTC)}
	sourceRule := baseRule("demo.sources", "sources.allowed", []string{"Dockerfile"}, map[string]any{
		"registries": []any{"ghcr.io"}, "requireDigest": true, "message": "Bad source",
	})
	findings, err := (SourcesAllowed{}).Evaluate(context.Background(), input, sourceRule)
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Message, "not allowed") {
		t.Fatalf("unexpected source result: %#v, %v", findings, err)
	}
	exceptionRule := baseRule("demo.exceptions", "exceptions.lifecycle", []string{".trivyignore.yaml"}, map[string]any{
		"collection": "vulnerabilities", "idField": "id", "reasonField": "statement",
		"ownerField": "owner", "ticketField": "ticket", "createdField": "created_at", "expiresField": "expired_at",
		"required": []any{"id", "reason", "owner", "ticket", "created", "expires"}, "maximumDays": 90,
	})
	findings, err = (ExceptionsLifecycle{}).Evaluate(context.Background(), input, exceptionRule)
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Message, "lifetime exceeds") {
		t.Fatalf("unexpected exception result: %#v, %v", findings, err)
	}
}

func TestStructuredImagesRequireImageContext(t *testing.T) {
	t.Parallel()
	value := map[string]any{
		"repository": "openhoo/hoolicy",
		"service":    map[string]any{"image": "evil.example/app:latest"},
		"chart": map[string]any{"image": map[string]any{
			"repository": "ghcr.io/openhoo/hoolicy",
			"digest":     "sha256:" + strings.Repeat("a", 64),
		}},
	}
	var images []string
	walkImages(value, "", func(_ string, image string) { images = append(images, image) })
	if len(images) != 2 {
		t.Fatalf("unexpected image references: %#v", images)
	}
	for _, image := range images {
		if image == "openhoo/hoolicy" {
			t.Fatalf("generic repository field was treated as image: %#v", images)
		}
	}
	if problem := imageProblem("ghcr.io/openhoo/hoolicy@sha256:bad", sourcesSpec{Registries: []string{"GHCR.IO"}, RequireDigest: true}); !strings.Contains(problem, "invalid") {
		t.Fatalf("expected malformed digest error, got %q", problem)
	}
	if problem := imageProblem("scratch", sourcesSpec{RequireDigest: true}); problem != "" {
		t.Fatalf("scratch must not require a digest: %q", problem)
	}
	value = map[string]any{"spec": map[string]any{"containers": []any{map[string]any{"name": "web", "image": "nginx:latest"}}}}
	images = nil
	walkImages(value, "", func(_ string, image string) { images = append(images, image) })
	if len(images) != 1 || images[0] != "nginx:latest" {
		t.Fatalf("short Docker Hub image was missed: %#v", images)
	}
	if problem := imageProblem(images[0], sourcesSpec{Registries: []string{"ghcr.io"}, RequireDigest: true}); !strings.Contains(problem, "docker.io") {
		t.Fatalf("expected short image registry finding, got %q", problem)
	}
}

func TestFindingTextUsesUnicodeCharacters(t *testing.T) {
	t.Parallel()
	rule := baseRule("demo.text", "text", nil, nil)
	message := strings.Repeat("界", 501)
	item := finding(rule, message, "README.md", "unicode", 1, 1)
	if got := len([]rune(item.Message)); got != 500 || !strings.HasSuffix(item.Message, "...") || !utf8.ValidString(item.Message) {
		t.Fatalf("unexpected truncated message: runes=%d valid=%v", got, utf8.ValidString(item.Message))
	}
	if line, column := lineColumn([]byte("a\né界x"), len([]byte("a\né界"))); line != 2 || column != 3 {
		t.Fatalf("lineColumn = %d:%d, want 2:3", line, column)
	}
}

func baseRule(id, kind string, files []string, spec map[string]any) sdk.Rule {
	return sdk.Rule{
		ID: id, Title: "Test rule", Description: "Test description.", Rationale: "Test rationale.",
		Remediation: "Correct the test fixture.", Severity: sdk.SeverityError, Kind: kind, Files: files, Spec: spec,
	}
}

func cloneMap(source map[string]any) map[string]any {
	target := make(map[string]any, len(source))
	for key, value := range source {
		target[key] = value
	}
	return target
}

func writeRuleFile(t testing.TB, root, path, body string) {
	t.Helper()
	absolute := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
