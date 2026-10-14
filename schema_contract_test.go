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
		// Published v1 files remain immutable. Latest schemas admit these
		// explicitly tested optional additions to the same on-disk versions.
		if name == "hoolicy.schema.json" || name == "report.schema.json" {
			definition, field, reference := "rule", "explanation", "rule-explanation.schema.json"
			if name == "report.schema.json" {
				definition, field, reference = "finding", "policy", "policy-context.schema.json"
			}
			properties := latest["$defs"].(map[string]any)[definition].(map[string]any)["properties"].(map[string]any)
			if !reflect.DeepEqual(properties[field], map[string]any{"$ref": reference}) {
				t.Fatalf("%s has an unreviewed %s extension", name, field)
			}
			delete(properties, field)
		}
		if name == "inventory.schema.json" {
			properties := latest["$defs"].(map[string]any)["rule"].(map[string]any)["properties"].(map[string]any)
			for field, expected := range map[string]any{"title": map[string]any{"type": "string"}, "remediation": map[string]any{"type": "string"}, "policy": map[string]any{"$ref": "policy-context.schema.json"}} {
				if !reflect.DeepEqual(properties[field], expected) {
					t.Fatalf("inventory has an unreviewed %s extension", field)
				}
				delete(properties, field)
			}
		}
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
