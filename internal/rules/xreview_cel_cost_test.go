package rules

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/openhoo/hoolicy/sdk"
)

// Extension functions are charged against costLimit only after they return,
// so the guard must reject an oversized call before it allocates. These
// tests are deliberately not parallel: they measure process allocation.
func TestCELExtensionCallsAreBoundedBeforeAllocation(t *testing.T) {
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	separator := strings.Repeat("a", 20000)
	for name, expression := range map[string]string{
		"join":     "lists.range(5000).map(x, 'a').join('" + separator + "').size() > 0",
		"replace":  "lists.range(5000).map(x, 'a').join('').replace('a', '" + separator + "').size() > 0",
		"flatten":  "[lists.range(100000)].all(big, lists.range(1000).map(x, big).flatten().size() > 0)",
		"distinct": "lists.range(100000).distinct().size() > 0",
		"sortBy":   "lists.range(2000).sortBy(x, -x).size() > 0",
	} {
		t.Run(name, func(t *testing.T) {
			rule := baseRule("demo.cel", "structured.cel", []string{"none.json"}, map[string]any{"expression": expression, "message": "x", "costLimit": 1_000_000})
			var before, after runtime.MemStats
			runtime.GC()
			runtime.ReadMemStats(&before)
			started := time.Now()
			_, err := kind.Evaluate(context.Background(), sdk.EvalContext{Repository: emptyRepository{}}, rule)
			elapsed := time.Since(started)
			runtime.ReadMemStats(&after)
			if err == nil || !strings.Contains(err.Error(), "cost limit") {
				t.Fatalf("expected cost-limit failure, got %v", err)
			}
			if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 32<<20 {
				t.Fatalf("allocated %d MiB before enforcing the cost limit", allocated>>20)
			}
			if elapsed > 2*time.Second {
				t.Fatalf("ran %s before enforcing the cost limit", elapsed)
			}
		})
	}
}

// string.format charges only its format string, so rendering a large shared
// structure must still be bounded by the rule's cost limit.
func TestCELFormatRenderingIsCharged(t *testing.T) {
	t.Parallel()
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.cel", "structured.cel", []string{"none.json"}, map[string]any{
		"expression": "[lists.range(1000)].all(big, '%s'.format([lists.range(2000).map(x, big)]).size() > 0)",
		"message":    "x", "costLimit": 1_000_000,
	})
	_, err = kind.Evaluate(context.Background(), sdk.EvalContext{Repository: emptyRepository{}}, rule)
	if err == nil || !strings.Contains(err.Error(), "cost limit") {
		t.Fatalf("format rendered an unbounded structure: %v", err)
	}
}

// The guard must not reject ordinary extension use within the budget.
func TestCELExtensionGuardAllowsBoundedCalls(t *testing.T) {
	t.Parallel()
	kind, err := newCEL()
	if err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{
		"[[1], [2, [3]]].flatten(2) == [1, 2, 3]",
		"[3, 1, 2, 2].distinct().sort() == [1, 2, 3]",
		"['b', 'a'].sortBy(x, x) == ['a', 'b']",
		"['a', 'b'].join(',').replace(',', '--') == 'a--b'",
		"'abc'.replace('', '-') == '-a-b-c-'",
		"'%s=%d %s'.format(['x', 1, [1, 'y']]) == 'x=1 [1, y]'",
		"lists.range(200).distinct().size() == 200",
	} {
		rule := baseRule("demo.cel", "structured.cel", []string{"none.json"}, map[string]any{"expression": expression, "message": "x"})
		if findings, err := kind.Evaluate(context.Background(), sdk.EvalContext{Repository: emptyRepository{}}, rule); err != nil || len(findings) != 0 {
			t.Fatalf("%s: findings=%v err=%v", expression, findings, err)
		}
	}
}
