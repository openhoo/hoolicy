package hoolicy

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestVersionedSchemasMatchPublishedV1Contracts(t *testing.T) {
	t.Parallel()
	entries, err := os.ReadDir("schemas")
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".schema.json") {
			continue
		}
		name := entry.Name()
		latest := loadSchemaObject(t, filepath.Join("schemas", name))
		versioned := loadSchemaObject(t, filepath.Join("schemas", "v1", name))
		latestID, _ := latest["$id"].(string)
		versionedID, _ := versioned["$id"].(string)
		wantVersionedID := strings.Replace(latestID, "/schemas/", "/schemas/v1/", 1)
		if latestID == "" || versionedID != wantVersionedID {
			t.Fatalf("%s schema IDs do not declare latest/v1 pair: latest=%q versioned=%q", name, latestID, versionedID)
		}
		delete(latest, "$id")
		delete(versioned, "$id")
		if !reflect.DeepEqual(latest, versioned) {
			t.Fatalf("%s differs from immutable schemas/v1 contract", name)
		}
	}
}

func loadSchemaObject(t *testing.T, path string) map[string]any {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return value
}
