package rules

import (
	"context"
	"strings"
	"testing"
	"time"

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
