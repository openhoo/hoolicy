package celenv

import (
	"reflect"
	"strings"
	"sync"
	"testing"

	"cel.dev/cel-go/cel"
	"cel.dev/cel-go/common/types"
	"cel.dev/cel-go/common/types/ref"
)

func guardedProgram(t *testing.T, environment *cel.Env, expression string, limit uint64) cel.Program {
	t.Helper()
	checked, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		t.Fatal(issues.Err())
	}
	options, err := ProgramOptions(environment, limit)
	if err != nil {
		t.Fatal(err)
	}
	program, err := environment.Program(checked, append([]cel.ProgramOption{cel.CostLimit(limit)}, options...)...)
	if err != nil {
		t.Fatal(err)
	}
	return program
}

func TestGuardedStructuralCallsPreserveCELSemantics(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	unknown := types.NewUnknown(42, types.NewAttributeTrail("missing"))
	for _, test := range []struct {
		expression string
		parameters map[string]any
	}{
		{expression: "[[1, 2], {'x': [3]}] == [[1.0, 2u], {'x': [3.0]}]"},
		{expression: "{'x': [[1], [2]]} != {'x': [[1], [3]]}"},
		{expression: "[b'abc', b'def'] == [b'abc', b'def']"},
		{expression: "dyn(null) != [null] && [null] != dyn(null)"},
		{expression: "[1] in [[2], [1]] && !(3 in [1, 2])"},
		{expression: "'x' in {'x': [1]} && !(dyn(1) in {'x': 1})"},
		{expression: "params.value in params.container", parameters: map[string]any{"value": []any{1, 2}, "container": []any{[]any{2, 3}, []any{1, 2}}}},
		{expression: "params.value in params.container", parameters: map[string]any{"value": "key", "container": map[string]any{"key": true}}},
		{expression: "params.value in params.container", parameters: map[string]any{"value": 1, "container": 2}},
		{expression: "params.value != 1", parameters: map[string]any{"value": types.NewErr("sentinel failure")}},
		{expression: "params.value != 1", parameters: map[string]any{"value": unknown}},
		{expression: "params.value == [1]", parameters: map[string]any{"value": []ref.Val{types.NewErr("nested failure")}}},
		{expression: "params.value != [1]", parameters: map[string]any{"value": []ref.Val{unknown}}},
		{expression: "params.value in params.container", parameters: map[string]any{"value": types.NewErr("sentinel failure"), "container": []any{1}}},
		{expression: "params.value in params.container", parameters: map[string]any{"value": unknown, "container": []any{1}}},
		{expression: "params.values.distinct()", parameters: map[string]any{"values": []any{[]any{1, 2}, []any{1, 2}, []any{2}}}},
	} {
		t.Run(test.expression, func(t *testing.T) {
			plain, err := compileAndProgram(environment, test.expression)
			if err != nil {
				t.Fatal(err)
			}
			guarded := guardedProgram(t, environment, test.expression, 100_000)
			activation := map[string]any{"params": test.parameters}
			want, _, wantErr := plain.Eval(activation)
			got, _, gotErr := guarded.Eval(activation)
			if (wantErr == nil) != (gotErr == nil) {
				t.Fatalf("native error=%v guarded error=%v", wantErr, gotErr)
			}
			if wantErr != nil {
				if wantErr.Error() != gotErr.Error() {
					t.Fatalf("native error=%v guarded error=%v", wantErr, gotErr)
				}
				return
			}
			if types.Equal(want, got) != types.True && !reflect.DeepEqual(want.Value(), got.Value()) {
				t.Fatalf("native result=%#v guarded result=%#v", want, got)
			}
		})
	}
}

func TestStructuralTraversalChargesAccumulate(t *testing.T) {
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	big := make([]any, 200)
	for index := range big {
		big[index] = index
	}
	nested := make([]any, 300)
	object := make(map[string]any, 300)
	for index := range nested {
		nested[index] = big
		object[string(rune(1000+index))] = big
	}
	empty := make([]any, 200)
	for index := range empty {
		empty[index] = []any{}
	}
	emptyNested := make([]any, 300)
	for index := range emptyNested {
		emptyNested[index] = empty
	}
	duplicate := make([]any, 50)
	for index := range duplicate {
		duplicate[index] = big
	}
	for _, test := range []struct {
		name, expression string
		limit            uint64
		value            any
	}{
		{name: "list equality", expression: "params.value == params.value", limit: 100_000, value: nested},
		{name: "map equality", expression: "params.value == params.value", limit: 100_000, value: object},
		{name: "dynamic membership", expression: "params.value in params.container", limit: 100_000, value: nested},
		{name: "empty flatten", expression: "params.value.flatten(2).size() == 0", limit: 100_000, value: emptyNested},
		{name: "nested distinct", expression: "params.value.distinct().size() == 1", limit: 12_000, value: duplicate},
	} {
		t.Run(test.name, func(t *testing.T) {
			activation := map[string]any{"params": map[string]any{"value": test.value, "container": []any{test.value}}}
			program := guardedProgram(t, environment, test.expression, test.limit)
			if result, details, err := program.Eval(activation); err != nil || result != types.True || details.ActualCost() == nil {
				t.Fatalf("bounded individual call failed: result=%v err=%v", result, err)
			}
			program = guardedProgram(t, environment, "("+test.expression+") && ("+test.expression+")", test.limit)
			if _, _, err := program.Eval(activation); err == nil || !strings.Contains(err.Error(), "cost limit") {
				t.Fatalf("repeated traversal did not accumulate cost: %v", err)
			}
		})
	}
}

func TestGuardedStructuralProgramSupportsConcurrentEvaluation(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	program := guardedProgram(t, environment, "params.value == params.value && params.value in params.container", 100_000)
	value := []any{map[string]any{"items": []any{1, 2, 3}}}
	activation := map[string]any{"params": map[string]any{"value": value, "container": []any{value}}}
	var workers sync.WaitGroup
	for range 24 {
		workers.Go(func() {
			for range 10 {
				if result, _, err := program.Eval(activation); err != nil || result != types.True {
					t.Errorf("concurrent evaluation result=%v err=%v", result, err)
				}
			}
		})
	}
	workers.Wait()
}

func TestExtensionTraversalGuardCountsEmptyContainers(t *testing.T) {
	empty := types.NewRefValList(types.DefaultTypeAdapter, nil)
	row := make([]ref.Val, 300)
	for index := range row {
		row[index] = empty
	}
	shared := types.NewRefValList(types.DefaultTypeAdapter, row)
	outer := make([]ref.Val, 300)
	for index := range outer {
		outer[index] = shared
	}
	value := types.NewRefValList(types.DefaultTypeAdapter, outer)
	const limit = 20_000
	for _, test := range []struct {
		name string
		args []ref.Val
	}{
		{name: "flatten", args: []ref.Val{value, types.Int(2)}},
		{name: "format", args: []ref.Val{types.String("%s"), value}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if cost := guardedBound(test.name)(test.args, limit); cost <= limit {
				t.Fatalf("pre-call guard ignored empty containers: cost=%d limit=%d", cost, limit)
			}
		})
	}
}

func TestFormatPreCallGuardCountsEmptyStrings(t *testing.T) {
	leaf := types.String("")
	row := make([]ref.Val, 300)
	for index := range row {
		row[index] = leaf
	}
	shared := types.NewRefValList(types.DefaultTypeAdapter, row)
	outer := make([]ref.Val, 300)
	for index := range outer {
		outer[index] = shared
	}
	value := types.NewRefValList(types.DefaultTypeAdapter, outer)
	if cost := formatBound([]ref.Val{types.String("%s"), value}, 20_000); cost <= 20_000 {
		t.Fatalf("pre-call format guard ignored empty string visits: cost=%d", cost)
	}
}
