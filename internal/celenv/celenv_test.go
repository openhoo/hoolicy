package celenv

import (
	"sort"
	"strings"
	"testing"

	"cel.dev/cel-go/cel"
)

func TestReferencesPackUsesCheckedAST(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for expression, want := range map[string]bool{
		"pack.limit > 1":                          true,
		"has(pack.limit)":                         true,
		"'limit' in pack":                         true,
		"[pack].size() == 1":                      true,
		"[1].all(x, x < pack.limit)":              true,
		"[pack].all(pack, pack.size() >= 0)":      true, // range reads the variable
		"[1].all(pack, pack > 0)":                 false,
		"[1].map(pack, pack).size() == 1":         false,
		"'pack' in params":                        false,
		"params.pack == 1":                        false,
		"documents.all(d, d.path == 'pack')":      false,
		"documents.all(d, d.data.pack == 'pack')": false,
		"true": false,
	} {
		got, err := ReferencesPack(environment, expression)
		if err != nil {
			t.Fatalf("%s: %v", expression, err)
		}
		if got != want {
			t.Fatalf("%s: references pack = %v, want %v", expression, got, want)
		}
	}
	if _, err := ReferencesPack(environment, "pack =="); err == nil {
		t.Fatal("invalid expression accepted")
	}
}

func TestEnvironmentProvidesOnlyDeterministicPinnedExtensions(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for _, expression := range []string{
		"[[1], [2, [3]]].flatten() == [1, 2, [3]]",
		"[[1], [2, [3]]].flatten(2) == [1, 2, 3]",
		"[3, 1, 2].sort() == [1, 2, 3]",
		"[1, 1, 2].distinct() == [1, 2]",
		"lists.range(3) == [0, 1, 2]",
		"['a', 'b'].join(',') == 'a,b'",
		"'a,b'.split(',') == ['a', 'b']",
		"'%s=%d'.format(['x', 1]) == 'x=1'",
		"{'a': 1}.all(k, v, k == 'a' && v == 1)",
		"[10, 20].exists(i, v, i == 1 && v == 20)",
		"{'a': 1}.transformList(k, v, k + string(v)) == ['a1']",
	} {
		program, err := compileAndProgram(environment, expression)
		if err != nil {
			t.Fatalf("%s: %v", expression, err)
		}
		result, _, err := program.Eval(map[string]any{})
		if err != nil || result.Value() != true {
			t.Fatalf("%s: result=%v err=%v", expression, result, err)
		}
	}
	for _, expression := range []string{
		"sets.contains([1], [1])",
		"math.greatest(1, 2) == 2",
		"isIP('127.0.0.1')",
		"regex.extract('a', 'a') == optional.of('a')",
		"base64.encode(b'a') == 'YQ=='",
	} {
		if _, issues := environment.Compile(expression); issues == nil || issues.Err() == nil {
			t.Fatalf("unexpected extension available: %s", expression)
		}
	}
}

func compileAndProgram(environment *cel.Env, expression string) (cel.Program, error) {
	checked, issues := environment.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, issues.Err()
	}
	return environment.Program(checked)
}

func TestReadsOfPackDistinguishesConstantAndDynamicReads(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for expression, want := range map[string]struct {
		names   string
		dynamic bool
	}{
		"pack.limit > 1 && has(pack.optional)": {names: "limit,optional"},
		"pack['environment'] == 'prod'":        {names: "environment"},
		"'limit' in pack":                      {dynamic: true},
		"documents.all(d, pack[d.path] == 1)":  {dynamic: true},
		"pack.size() == 0":                     {dynamic: true},
		"params.limit == 1":                    {},
	} {
		reads, err := ReadsOfPack(environment, expression)
		if err != nil {
			t.Fatalf("%s: %v", expression, err)
		}
		var names []string
		for name := range reads.Names {
			names = append(names, name)
		}
		sort.Strings(names)
		if strings.Join(names, ",") != want.names || reads.Dynamic != want.dynamic {
			t.Fatalf("%s: names=%v dynamic=%v", expression, names, reads.Dynamic)
		}
	}
}

// A root-qualified .pack identifier reads the same variable as pack, even
// inside a comprehension that binds a local variable named pack.
func TestReadsOfPackRecognizesRootQualifiedIdentifier(t *testing.T) {
	t.Parallel()
	environment, err := New()
	if err != nil {
		t.Fatal(err)
	}
	for expression, want := range map[string]struct {
		names   string
		dynamic bool
	}{
		"has(.pack.strict)":                   {names: "strict"},
		".pack['limit'] > 1":                  {names: "limit"},
		"[1].exists(pack, has(.pack.strict))": {names: "strict"},
		"'limit' in .pack":                    {dynamic: true},
	} {
		reads, err := ReadsOfPack(environment, expression)
		if err != nil {
			t.Fatalf("%s: %v", expression, err)
		}
		var names []string
		for name := range reads.Names {
			names = append(names, name)
		}
		sort.Strings(names)
		if !reads.Any || strings.Join(names, ",") != want.names || reads.Dynamic != want.dynamic {
			t.Fatalf("%s: any=%v names=%v dynamic=%v", expression, reads.Any, names, reads.Dynamic)
		}
	}
}
