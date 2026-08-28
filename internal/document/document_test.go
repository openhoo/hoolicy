package document

import (
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

func TestParseFormatsAndRejectAmbiguity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name, path, data string
		want             int
	}{
		{name: "json", path: "a.json", data: `{"count": 2}`, want: 1},
		{name: "json UTF-8 BOM", path: "bom.json", data: "\ufeff{\"count\": 2}", want: 1},
		{name: "yaml documents", path: "a.yaml", data: "a: 1\n---\nb: 2\n", want: 2},
		{name: "toml", path: "a.toml", data: "name = \"demo\"\n", want: 1},
		{name: "xml", path: "a.xml", data: "<root><item id=\"1\"/></root>", want: 1},
		{name: "dotenv", path: ".env", data: "A=one\nB=two\n", want: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			documents, err := Parse(sdk.File{Path: test.path, Data: []byte(test.data)}, "auto")
			if err != nil {
				t.Fatal(err)
			}
			if len(documents) != test.want {
				t.Fatalf("got %d documents, want %d", len(documents), test.want)
			}
		})
	}
	for _, test := range []struct{ path, data string }{
		{path: "bad.json", data: `{} {}`},
		{path: "bad.yaml", data: "a: 1\na: 2\n"},
		{path: "bad.jsonc", data: "// comment\n{}"},
	} {
		if _, err := Parse(sdk.File{Path: test.path, Data: []byte(test.data)}, "auto"); err == nil {
			t.Fatalf("expected %s to fail", test.path)
		}
	}
}

func TestXMLRejectsTrailingRootElement(t *testing.T) {
	t.Parallel()
	file := sdk.File{Path: "invalid.xml", Data: []byte("<first/><second/>")}
	if _, err := Parse(file, "xml"); err == nil {
		t.Fatal("expected trailing XML rejection")
	}
	file = sdk.File{Path: "valid.xml", Data: []byte("<first/><?processed ok?>")}
	if _, err := Parse(file, "xml"); err != nil {
		t.Fatalf("valid trailing processing instruction rejected: %v", err)
	}
}

func FuzzParseJSON(f *testing.F) {
	f.Add([]byte(`{"ok": true}`))
	f.Add([]byte(`[]`))
	f.Add([]byte(`{} {}`))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(sdk.File{Path: "fuzz.json", Data: data}, "json")
	})
}
