package rules

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestCELStructuralOperationsRespectBudget(t *testing.T) {
	for name, expression := range map[string]string{
		"equality":          "[lists.range(1000)].all(big, [lists.range(1200).map(x, big)].all(shared, shared == shared))",
		"inequality":        "[lists.range(1000)].all(big, [lists.range(1200).map(x, big)].all(shared, !(shared != shared)))",
		"membership":        "[lists.range(1000)].all(big, [lists.range(1200).map(x, big)].all(shared, shared in [shared]))",
		"distinct":          "[lists.range(10000)].all(big, lists.range(400).map(x, big).distinct().size() == 1)",
		"formatEmptyLists":  "[lists.range(1000).map(x, [])].all(big, '%s'.format([lists.range(1200).map(x, big)]).size() > 0)",
		"flattenEmptyLists": "[lists.range(1000).map(x, [])].all(big, lists.range(1200).map(x, big).flatten(2).size() == 0)",
	} {
		t.Run(name, func(t *testing.T) {
			kind, err := newCEL()
			if err != nil {
				t.Fatal(err)
			}
			rule := baseRule("smoke.cel", "structured.cel", []string{"none.json"}, map[string]any{"expression": expression, "message": "x", "costLimit": 1_000_000})
			if name == "equality" || name == "inequality" || name == "membership" {
				rule.Spec["costLimit"] = 100_000
			}
			started := time.Now()
			metrics := sdk.EvaluationMetrics{}
			_, err = kind.Evaluate(context.Background(), sdk.EvalContext{Repository: emptyRepository{}, Metrics: &metrics}, rule)
			t.Logf("elapsed=%s reportedCost=%d err=%v", time.Since(started), metrics.CELCost, err)
			if err == nil || !strings.Contains(err.Error(), "cost limit") {
				t.Fatalf("unbounded structural operation accepted: %v", err)
			}
		})
	}
}

func TestCELCanceledContextRejectsNonComprehension(t *testing.T) {
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rule := baseRule("smoke.cel", "structured.cel", []string{"none.json"}, map[string]any{"expression": "true", "message": "x"})
	if _, err := kind.Evaluate(ctx, sdk.EvalContext{Repository: emptyRepository{}}, rule); err == nil {
		t.Fatal("canceled evaluation accepted")
	}
}

func TestCELRejectsJSONNumbersOutsideSupportedRange(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name, number, expression string
	}{
		{"nonzero underflow", "1e-324", "documents.all(d, d.data.a == 0)"},
		{"negative underflow", "-1e-999999999", "documents.all(d, d.data.a == 0)"},
		{"oversized integer", "18446744073709551616", "documents.all(d, d.data.a == 18446744073709551616.0)"},
		{"nested overflow", "1e999999999", "documents.all(d, d.data == {'a': 0})"},
	} {
		t.Run(test.name, func(t *testing.T) {
			root := t.TempDir()
			writeRuleFile(t, root, "input.json", `{"a":`+test.number+`}`)
			repo, err := repository.Open(root, repository.Options{})
			if err != nil {
				t.Fatal(err)
			}
			rule := baseRule("smoke.cel", "structured.cel", []string{"input.json"}, map[string]any{"expression": test.expression, "message": "x"})
			findings, err := (CEL{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
			if err == nil || !strings.Contains(err.Error(), "numeric range") {
				t.Fatalf("unsupported JSON number became a policy result: findings=%v err=%v", findings, err)
			}
		})
	}
}

func TestCELAcceptsRepresentableJSONNumbers(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "input.json", `{"unsigned":18446744073709551615,"integer":9007199254740993,"decimal":1.5,"subnormal":5e-324,"zero":0e-999999999,"text":"1e999999999"}`)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("smoke.cel", "structured.cel", []string{"input.json"}, map[string]any{
		"expression": "documents.all(d, d.data.unsigned == 18446744073709551615u && d.data.integer == 9007199254740993 && d.data.decimal == 1.5 && d.data.subnormal > 0 && d.data.zero == 0 && d.data.text == '1e999999999')",
		"message":    "x",
	})
	if findings, err := (CEL{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule); err != nil || len(findings) != 0 {
		t.Fatalf("representable JSON values changed: findings=%v err=%v", findings, err)
	}
}
