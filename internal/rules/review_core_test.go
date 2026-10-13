package rules

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/sdk"
)

// Merge-key alias graphs ("billion laughs") must stay bounded on the
// lenient foreign-YAML path.
func TestStructuredImageWalkBoundsAliasExpansion(t *testing.T) {
	t.Parallel()
	var builder strings.Builder
	builder.WriteString("a0: &a0 {image: docker.io/x:1}\n")
	for level := 1; level <= 30; level++ {
		builder.WriteString("a")
		builder.WriteString(itoa(level))
		builder.WriteString(": &a")
		builder.WriteString(itoa(level))
		builder.WriteString(" [*a")
		builder.WriteString(itoa(level - 1))
		builder.WriteString(", *a")
		builder.WriteString(itoa(level - 1))
		builder.WriteString("]\n")
	}
	file := sdk.File{Path: t.Name() + ".yml", Data: []byte(builder.String())}
	rule := baseRule("demo.sources", "sources.allowed", nil, nil)
	done := make(chan error, 1)
	go func() {
		findings, err := checkStructuredImages(rule, file, sourcesSpec{Registries: []string{"allowed.example.com"}}, "Bad", nil)
		// Each alias node is walked at most once per parent key, so 31
		// levels yield at most 31 reports instead of 2^30 expansions.
		if err == nil && (len(findings) == 0 || len(findings) > 31) {
			err = errors.New("aliased image findings are missing or unbounded")
		}
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("alias graph walk did not terminate promptly")
	}
}

func itoa(value int) string {
	if value < 10 {
		return string(rune('0' + value))
	}
	return itoa(value/10) + string(rune('0'+value%10))
}

func TestCELEvaluationObservesContextCancellation(t *testing.T) {
	t.Parallel()
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.cel", "structured.cel", []string{"none.json"}, map[string]any{
		"expression": "[1,2,3,4,5,6,7,8,9,10].all(a, [1,2,3,4,5,6,7,8,9,10].all(b, [1,2,3,4,5,6,7,8,9,10].all(c, true)))",
		"message":    "x", "costLimit": 1_000_000,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	repo := emptyRepository{}
	if _, err := kind.Evaluate(ctx, sdk.EvalContext{Repository: repo}, rule); err == nil || !strings.Contains(err.Error(), "cancel") {
		t.Fatalf("cancelled CEL evaluation continued: %v", err)
	}
}

type emptyRepository struct{}

func (emptyRepository) Root() string                            { return "/repo" }
func (emptyRepository) AllFiles() []sdk.File                    { return nil }
func (emptyRepository) Match(_, _ []string) ([]sdk.File, error) { return nil, nil }
func (emptyRepository) Read(path string) (sdk.File, error) {
	return sdk.File{}, errors.New("missing " + path)
}
func (emptyRepository) Git() sdk.GitContext { return sdk.GitContext{} }

func TestCELExtensionEvaluationObservesRuleTimeout(t *testing.T) {
	t.Parallel()
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.cel", "structured.cel", []string{"none.json"}, map[string]any{
		"expression": "lists.range(100000).all(a, lists.range(100000).map(b, [a, b]).flatten().size() > 0)",
		"message":    "x", "costLimit": 1_000_000,
	})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	_, err = kind.Evaluate(ctx, sdk.EvalContext{Repository: emptyRepository{}}, rule)
	if err == nil || !strings.Contains(err.Error(), "interrupted") {
		t.Fatalf("extension evaluation was not interrupted: %v", err)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("extension evaluation ignored its deadline for %s", elapsed)
	}
}

func TestNuGetRejectsAmbiguousXMLAndMissingRoot(t *testing.T) {
	t.Parallel()
	rule := baseRule("smoke.sources", "sources.allowed", nil, nil)
	spec := sourcesSpec{NuGet: []string{"https://api.nuget.org/v3/index.json"}}
	for _, data := range []string{
		`<configuration><packageSources><add key="test" value="https://evil.example.com/index.json" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>`,
		`<configuration xmlns:a="urn:a" xmlns:b="urn:b"><packageSources><add key="test" a:value="https://evil.example.com/index.json" b:value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>`,
		`<configuration/><configuration/>`,
		`<configuration/>trailing`,
		``,
	} {
		if findings, err := checkNuGetSources(rule, sdk.File{Path: "nuget.config", Data: []byte(data)}, spec, "Bad source"); err == nil {
			t.Fatalf("ambiguous or incomplete NuGet XML accepted: data=%s findings=%v", data, findings)
		}
	}
	for _, data := range []string{
		`<configuration><packageSources><add key="test" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration>`,
		`<?xml version="1.0"?><configuration xmlns:a="urn:a"><packageSources><add a:key="test" value="https://api.nuget.org/v3/index.json"/></packageSources></configuration><!--end-->`,
	} {
		if findings, err := checkNuGetSources(rule, sdk.File{Path: "nuget.config", Data: []byte(data)}, spec, "Bad source"); err != nil || len(findings) != 0 {
			t.Fatalf("valid NuGet XML rejected: data=%s findings=%v err=%v", data, findings, err)
		}
	}
}

func TestNuGetNestedElementsDoNotHideOuterSources(t *testing.T) {
	t.Parallel()
	file := sdk.File{Path: "nuget.config", Data: []byte(`<configuration><packageSources><packageSources/><add key="bad" value="https://evil.example.com/index.json"/></packageSources></configuration>`)}
	rule := baseRule("smoke.sources", "sources.allowed", nil, nil)
	spec := sourcesSpec{NuGet: []string{"https://api.nuget.org/v3/index.json"}}
	findings, err := checkNuGetSources(rule, file, spec, "Bad source")
	if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Message, "evil.example.com") {
		t.Fatalf("nested close stopped checking outer sources: findings=%v err=%v", findings, err)
	}
}
