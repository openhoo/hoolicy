package rules

import (
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

func TestScalarJSONEditTargetsExactPointerAndToken(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, data, pointer, want string
		old, replacement          any
	}{
		{"numeric prefix in sibling", `{"wanted":{"version":1},"other":{"version":10}}`, "/wanted/version", `{"wanted":{"version":2},"other":{"version":10}}`, int64(1), int64(2)},
		{"different number spelling", `{"wanted":{"version":1.0},"other":{"version":1}}`, "/wanted/version", `{"wanted":{"version":2},"other":{"version":1}}`, float64(1), int64(2)},
		{"escaped JSON property", `{"\u0076ersion":"one"}`, "/version", `{"\u0076ersion":"two"}`, "one", "two"},
		{"escaped pointer", `{"a/b":{"~key":"one"},"~key":"one"}`, "/a~1b/~0key", `{"a/b":{"~key":"two"},"~key":"one"}`, "one", "two"},
		{"escaped string value", `{"version":"\u006fne"}`, "/version", `{"version":"two"}`, "one", "two"},
		{"BOM", "\ufeff" + `{"version":1}`, "/version", "\ufeff" + `{"version":2}`, int64(1), int64(2)},
		{"root scalar", `  "one"  `, "", `  "two"  `, "one", "two"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file := sdk.File{Path: "target.json", Data: []byte(test.data)}
			edit, err := scalarJSONEdit(file, test.pointer, test.old, test.replacement)
			if err != nil {
				t.Fatal(err)
			}
			got := string(file.Data[:edit.Start]) + string(edit.Replacement) + string(file.Data[edit.End:])
			if got != test.want {
				t.Fatalf("edited %s, want %s", got, test.want)
			}
		})
	}
}

func TestScalarJSONEditRejectsStaleAndCompositeValues(t *testing.T) {
	t.Parallel()
	file := sdk.File{Path: "target.json", Data: []byte(`{"version":10}`)}
	if _, err := scalarJSONEdit(file, "/version", int64(1), int64(2)); err == nil {
		t.Fatal("numeric prefix accepted as complete value")
	}
	if _, err := scalarJSONEdit(file, "/missing", int64(10), int64(2)); err == nil {
		t.Fatal("missing pointer accepted")
	}
	for _, value := range []any{map[string]any{"a": int64(1)}, []any{"one"}} {
		if _, err := scalarJSONEdit(file, "/version", int64(10), value); err == nil || !strings.Contains(err.Error(), "scalar") {
			t.Fatalf("composite replacement accepted: %v", err)
		}
	}
}
