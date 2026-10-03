package document

import (
	"strings"
	"sync"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

func TestConcurrentParseCacheKeepsOneEvictionEntryPerKey(t *testing.T) {
	file := sdk.File{Path: t.Name() + ".json", Data: []byte("[" + strings.Repeat("0,", 16384) + "0]")}
	start := make(chan struct{})
	var workers sync.WaitGroup
	for range 16 {
		workers.Go(func() {
			<-start
			if _, _, err := ParseCached(file, "json"); err != nil {
				t.Error(err)
			}
		})
	}
	close(start)
	workers.Wait()
	sharedParseCache.Lock()
	defer sharedParseCache.Unlock()
	seen := map[string]bool{}
	for _, key := range sharedParseCache.order {
		if seen[key] {
			t.Fatal("concurrent misses duplicated a cache eviction key")
		}
		seen[key] = true
	}
	if len(seen) != len(sharedParseCache.entries) || len(seen) > parseCacheLimit {
		t.Fatalf("cache queue and entries diverged: %d vs %d", len(seen), len(sharedParseCache.entries))
	}
}

func TestJSONRejectsDuplicateObjectKeys(t *testing.T) {
	t.Parallel()
	for _, data := range []string{
		`{"producer":"trusted","producer":"other"}`,
		`{"outer":{"ok":true,"ok":false}}`,
		`[{"version":1,"version":2}]`,
		`{"key":1,"\u006bey":2}`,
	} {
		if _, err := Parse(sdk.File{Path: "ambiguous.json", Data: []byte(data)}, "json"); err == nil || !strings.Contains(err.Error(), "duplicate key") {
			t.Fatalf("ambiguous input %s: %v", data, err)
		}
	}
	if _, err := Parse(sdk.File{Path: "distinct.json", Data: []byte(`{"a":{"key":1},"b":{"key":2}}`)}, "json"); err != nil {
		t.Fatalf("keys in different objects must remain valid: %v", err)
	}
}

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
