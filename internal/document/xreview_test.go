package document

import (
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

// The lenient node parse used for foreign YAML must not populate the strict
// parse cache: a later strict consumer would receive node-only documents
// (Data == nil) for a file whose duplicate keys it must reject.
func TestLenientYAMLNodeParseDoesNotPoisonStrictCache(t *testing.T) {
	t.Parallel()
	file := sdk.File{Path: t.Name() + "/.gitlab-ci.yml", Data: []byte("job:\n  image: a\njob:\n  image: b\n")}
	if _, _, err := ParseCachedYAMLNodes(file); err != nil {
		t.Fatal(err)
	}
	documents, _, err := ParseCached(file, "yaml")
	if err == nil || !strings.Contains(err.Error(), "duplicate key") {
		t.Fatalf("strict YAML parse accepted duplicate keys after lenient parse: documents=%#v err=%v", documents, err)
	}
	clean := sdk.File{Path: t.Name() + "/clean.yml", Data: []byte("job:\n  image: a\n")}
	if _, _, err := ParseCachedYAMLNodes(clean); err != nil {
		t.Fatal(err)
	}
	documents, _, err = ParseCached(clean, "yaml")
	if err != nil || len(documents) != 1 || documents[0].Data == nil {
		t.Fatalf("strict YAML parse returned node-only documents: %#v %v", documents, err)
	}
}

// Private parser cache namespaces must not be selectable by a document format.
func TestParseCacheRejectsPrivateNamespaceFormats(t *testing.T) {
	file := sdk.File{Path: t.TempDir() + "/foreign.yaml", Data: []byte("job: a\njob: b\n")}
	if _, _, err := ParseCachedYAMLNodes(file); err != nil {
		t.Fatal(err)
	}
	if parsed, hit, err := ParseCached(file, "yaml\x00lenient-nodes"); err == nil {
		t.Fatalf("unknown format loaded private cached YAML: %#v hit=%v", parsed, hit)
	}
	file = sdk.File{Path: t.TempDir() + "/precise.json", Data: []byte(`{"a":1}`)}
	if _, _, err := ParseCachedPreservingJSONNumbers(file, "json"); err != nil {
		t.Fatal(err)
	}
	if parsed, hit, err := ParseCached(file, "json\x00preserve-json-numbers"); err == nil {
		t.Fatalf("unknown format loaded precise cache: %#v hit=%v", parsed, hit)
	}
}
