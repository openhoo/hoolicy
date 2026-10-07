package rules

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestStructuredFieldsFormats(t *testing.T) {
	t.Parallel()
	for _, test := range []struct{ path, data string }{
		{"config.json", `{"service":{"enabled":true,"port":443,"name":"api-prod","roles":["reader","writer"]},"a/b":{"~key":null}}`},
		{"config.yaml", "service:\n  enabled: true\n  port: 443\n  name: api-prod\n  roles: [reader, writer]\na/b:\n  '~key': null\n"},
		{"config.toml", "[service]\nenabled = true\nport = 443\nname = 'api-prod'\nroles = ['reader', 'writer']\n"},
	} {
		t.Run(test.path, func(t *testing.T) {
			fields := []any{
				map[string]any{"pointer": "/service/enabled", "required": true, "allowedValues": []any{true}},
				map[string]any{"pointer": "/service/port", "type": "integer", "minimum": 1, "maximum": 65535},
				map[string]any{"pointer": "/service/name", "pattern": "^api-[a-z]+$"},
				map[string]any{"pointer": "/service/roles", "type": "array", "minItems": 2, "maxItems": 3, "requiredItems": []any{"reader"}, "uniqueItems": true},
				map[string]any{"pointer": "/service/roles/0", "allowedValues": []any{"reader"}},
				map[string]any{"pointer": "/secret", "forbidden": true},
				map[string]any{"pointer": "/missing", "type": "string"},
			}
			if !strings.HasSuffix(test.path, ".toml") {
				fields = append(fields, map[string]any{"pointer": "/a~1b/~0key", "required": true, "allowedValues": []any{nil}, "type": "null"})
			}
			findings, err := evaluateStructured(t, context.Background(), test.path, test.data, map[string]any{"fields": fields})
			if err != nil || len(findings) != 0 {
				t.Fatalf("findings=%#v err=%v", findings, err)
			}
		})
	}
}

func TestStructuredFieldsViolationReasons(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		field        map[string]any
		data, reason string
	}{
		{map[string]any{"pointer": "/value", "required": true}, `{}`, "is required"},
		{map[string]any{"pointer": "/value", "forbidden": true}, `{"value":null}`, "is forbidden"},
		{map[string]any{"pointer": "/value", "type": "string"}, `{"value":null}`, "must have type string"},
		{map[string]any{"pointer": "/value", "type": "integer"}, `{"value":1.5}`, "must have type integer"},
		{map[string]any{"pointer": "/value", "allowedValues": []any{"allowed"}}, `{"value":"private-secret-do-not-print"}`, "must match an allowed value"},
		{map[string]any{"pointer": "/value", "pattern": "^safe$"}, `{"value":"unsafe"}`, "must match the required string pattern"},
		{map[string]any{"pointer": "/value", "minimum": 5}, `{"value":4}`, "is below the minimum"},
		{map[string]any{"pointer": "/value", "maximum": 5}, `{"value":6}`, "exceeds the maximum"},
		{map[string]any{"pointer": "/value", "minimum": 5}, `{"value":"6"}`, "must be a number"},
		{map[string]any{"pointer": "/value", "minItems": 2}, `{"value":[1]}`, "has fewer than minItems"},
		{map[string]any{"pointer": "/value", "maxItems": 1}, `{"value":[1,2]}`, "has more than maxItems"},
		{map[string]any{"pointer": "/value", "uniqueItems": true}, `{"value":[{"a":1,"b":2},{"b":2,"a":1}]}`, "must contain unique items"},
		{map[string]any{"pointer": "/value", "requiredItems": []any{"reader"}}, `{"value":["writer"]}`, "is missing a required item"},
		{map[string]any{"pointer": "/value", "minItems": 1}, `{"value":{}}`, "must be an array"},
		{map[string]any{"pointer": "/value/child", "required": true}, `{"value":false}`, "is required"},
	} {
		t.Run(test.reason, func(t *testing.T) {
			findings, err := evaluateStructured(t, context.Background(), "config.json", test.data, map[string]any{"fields": []any{test.field}})
			if err != nil || len(findings) != 1 || !strings.Contains(findings[0].Message, test.reason) {
				t.Fatalf("findings=%#v err=%v", findings, err)
			}
			if strings.Contains(findings[0].Message, "private-secret-do-not-print") {
				t.Fatal("finding leaked a configuration value")
			}
			if findings[0].Location.Path != "config.json" || findings[0].Key == "" {
				t.Fatal("finding lacks stable document/pointer identity")
			}
		})
	}
}

func TestStructuredFieldsRejectInvalidSpec(t *testing.T) {
	t.Parallel()
	for _, spec := range []map[string]any{
		{"fields": []any{}},
		{"fields": []any{map[string]any{"required": true}}},
		{"fields": []any{map[string]any{"pointer": "bad", "required": true}}},
		{"fields": []any{map[string]any{"pointer": "/~2", "required": true}}},
		{"fields": []any{map[string]any{"pointer": "/a", "required": true}, map[string]any{"pointer": "/a", "forbidden": true}}},
		{"fields": []any{map[string]any{"pointer": "/a"}}},
		{"fields": []any{map[string]any{"pointer": "/a", "required": true, "forbidden": true}}},
		{"fields": []any{map[string]any{"pointer": "/a", "type": "bogus"}}},
		{"fields": []any{map[string]any{"pointer": "/a", "pattern": "["}}},
		{"fields": []any{map[string]any{"pointer": "/a", "pattern": "a", "type": "boolean"}}},
		{"fields": []any{map[string]any{"pointer": "/a", "minimum": 2, "maximum": 1}}},
		{"fields": []any{map[string]any{"pointer": "/a", "minimum": 1, "type": "array"}}},
		{"fields": []any{map[string]any{"pointer": "/a", "minItems": -1}}},
		{"fields": []any{map[string]any{"pointer": "/a", "minItems": 2, "maxItems": 1}}},
		{"fields": []any{map[string]any{"pointer": "/a", "minItems": 2, "type": "string"}}},
		{"fields": []any{map[string]any{"pointer": "/a", "allowedValues": []any{}}}},
		{"fields": []any{map[string]any{"pointer": "/a", "required": true, "unknown": true}}},
		{"format": "shell", "fields": []any{map[string]any{"pointer": "/a", "required": true}}},
		{"unknown": true, "fields": []any{map[string]any{"pointer": "/a", "required": true}}},
	} {
		rule := baseRule("demo.fields", "structured.fields", []string{"config.json"}, spec)
		if err := (StructuredFields{}).Validate(rule); err == nil {
			t.Fatalf("invalid spec accepted: %#v", spec)
		}
	}
}

func TestStructuredFieldsEmptyMalformedAndCancellation(t *testing.T) {
	t.Parallel()
	spec := map[string]any{"fields": []any{map[string]any{"pointer": "/a", "required": true}}}
	findings, err := evaluateStructured(t, context.Background(), "empty.yaml", "", spec)
	if err != nil || len(findings) != 1 || findings[0].Key != "no-documents" {
		t.Fatalf("empty file: %#v %v", findings, err)
	}
	for _, data := range []string{`{"a":1,"a":2}`, `{"a":`} {
		if _, err := evaluateStructured(t, context.Background(), "config.json", data, spec); err == nil {
			t.Fatalf("malformed document accepted: %s", data)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := evaluateStructured(t, ctx, "config.json", `{}`, spec); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation ignored: %v", err)
	}
}

func TestStructuredFieldsMultipleDocumentsAndNull(t *testing.T) {
	t.Parallel()
	fields := []any{map[string]any{"pointer": "/a", "required": true, "type": "null"}}
	findings, err := evaluateStructured(t, context.Background(), "config.yaml", "a: null\n---\na: false\n---\nother: 1\n", map[string]any{"fields": fields})
	if err != nil || len(findings) != 2 || findings[0].Key == findings[1].Key || findings[0].Location.Line == findings[1].Location.Line {
		t.Fatalf("multi-document findings: %#v %v", findings, err)
	}
}

func TestStructuredFieldsLargeNumbersAndPointerSyntax(t *testing.T) {
	t.Parallel()
	fields := []any{map[string]any{"pointer": "/a", "type": "integer", "minimum": 9007199254740992}}
	findings, err := evaluateStructured(t, context.Background(), "config.json", `{"a":9007199254740991}`, map[string]any{"fields": fields})
	if err != nil || len(findings) != 1 {
		t.Fatalf("large number rounded: %#v %v", findings, err)
	}
	for _, pointer := range []string{"/a/01", "/a/-1", "/a/+1", "/a/-", "/a/999999999999999999999999999"} {
		if _, exists := structuredPointer(map[string]any{"a": []any{0, 1}}, pointer); exists {
			t.Fatalf("noncanonical index accepted: %s", pointer)
		}
	}
	if !structuredType(1.0, "integer") || structuredType("1", "number") {
		t.Fatal("numeric type mismatch")
	}
}

func TestStructuredFieldsNoFilesAndRoot(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	spec := map[string]any{"fields": []any{map[string]any{"pointer": "", "type": "object"}}}
	rule := baseRule("demo.fields", "structured.fields", []string{"config.json"}, spec)
	findings, err := (StructuredFields{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil || len(findings) != 1 || findings[0].Key != "no-files" {
		t.Fatalf("no files: %#v %v", findings, err)
	}
	rule.Spec["allowNoFiles"] = true
	findings, err = (StructuredFields{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil || len(findings) != 0 {
		t.Fatalf("optional no files: %#v %v", findings, err)
	}
	findings, err = evaluateStructured(t, context.Background(), "config.json", `{}`, spec)
	if err != nil || len(findings) != 0 {
		t.Fatalf("root pointer: %#v %v", findings, err)
	}
}

func evaluateStructured(t *testing.T, ctx context.Context, path, data string, spec map[string]any) ([]sdk.Finding, error) {
	t.Helper()
	root := t.TempDir()
	writeRuleFile(t, root, path, data)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.fields", "structured.fields", []string{path}, spec)
	return (StructuredFields{}).Evaluate(ctx, sdk.EvalContext{Repository: repo}, rule)
}

func TestStructuredFieldsEquivalentNumericValues(t *testing.T) {
	t.Parallel()
	fields := []any{map[string]any{"pointer": "/value", "uniqueItems": true}}
	findings, err := evaluateStructured(t, context.Background(), "config.json", `{"value":[1,1.0,1e0]}`, map[string]any{"fields": fields})
	if err != nil || len(findings) != 1 {
		t.Fatalf("equivalent values were distinct: %#v %v", findings, err)
	}
	fields = []any{map[string]any{"pointer": "/value", "allowedValues": []any{map[string]any{"number": 1}}}}
	findings, err = evaluateStructured(t, context.Background(), "config.json", `{"value":{"number":1.0}}`, map[string]any{"fields": fields})
	if err != nil || len(findings) != 0 {
		t.Fatalf("numeric equality mismatch: %#v %v", findings, err)
	}
}

func TestStructuredFieldsBoundsComparisonWork(t *testing.T) {
	t.Parallel()
	if _, ok := structuredNumber(json.Number("1e999999999")); ok {
		t.Fatal("unbounded exponent accepted")
	}
	pointer := "/value"
	items := make([]any, 100001)
	if _, err := structuredViolations(context.Background(), items, true, structuredField{Pointer: &pointer, UniqueItems: true}, nil); err == nil {
		t.Fatal("unbounded array comparison accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := structuredViolations(ctx, []any{1, 2, 3}, true, structuredField{Pointer: &pointer, UniqueItems: true}, nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("inner cancellation ignored: %v", err)
	}
}

func TestStructuredFieldsNumericBudgetErrorsAreOperational(t *testing.T) {
	t.Parallel()
	for _, field := range []map[string]any{
		{"pointer": "/value", "type": "number"},
		{"pointer": "/value", "type": "integer"},
		{"pointer": "/value", "minimum": 0},
		{"pointer": "/value", "maximum": 10},
	} {
		for _, number := range []string{"1e999999999", "1e-999999999", strings.Repeat("9", 4097)} {
			findings, err := evaluateStructured(t, context.Background(), "config.json", `{"value":`+number+`}`, map[string]any{"fields": []any{field}})
			if err == nil || len(findings) != 0 || !strings.Contains(err.Error(), "comparison limit exceeded") {
				t.Fatalf("budget must be operational for %#v: findings=%#v error=%v", field, findings, err)
			}
		}
	}
	findings, err := evaluateStructured(t, context.Background(), "config.json", `{"value":"not a number"}`, map[string]any{"fields": []any{map[string]any{"pointer": "/value", "type": "number"}}})
	if err != nil || len(findings) != 1 {
		t.Fatalf("wrong value type should remain a policy finding: %#v %v", findings, err)
	}
}

func TestStructuredFieldsNestedArrayComparisonBudgetAndCancellation(t *testing.T) {
	t.Parallel()
	data := `{"value":{"nested":[` + strings.Repeat("null,", 100000) + `null]}}`
	findings, err := evaluateStructured(t, context.Background(), "config.json", data, map[string]any{"fields": []any{map[string]any{"pointer": "/value", "allowedValues": []any{nil}}}})
	if err == nil || len(findings) != 0 || !strings.Contains(err.Error(), "array comparison limit exceeded") {
		t.Fatalf("nested comparison budget escaped: %#v %v", findings, err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := structuredCanonical(ctx, map[string]any{"nested": []any{1, 2, 3}}, 0); !errors.Is(err, context.Canceled) {
		t.Fatalf("nested cancellation escaped: %v", err)
	}
}
