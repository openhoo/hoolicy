package celenv

import "testing"

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
