package rules

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

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
	if err := (CEL{}).Validate(celRule); err != nil {
		t.Fatal(err)
	}
	findings, err := (CEL{}).Evaluate(context.Background(), input, celRule)
	if err != nil {
		t.Fatal(err)
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

func writeRuleFile(t *testing.T, root, path, body string) {
	t.Helper()
	absolute := filepath.Join(root, filepath.FromSlash(path))
	if err := os.MkdirAll(filepath.Dir(absolute), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(absolute, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}
