package hoolicy

import (
	"path/filepath"
	"testing"

	"github.com/openhoo/hoolicy/internal/config"
)

func TestSupportedV0_1MinorLineInputsStillLoad(t *testing.T) {
	t.Parallel()
	root := filepath.Join("testdata", "compatibility", "v0.1")
	project, err := config.LoadProject(filepath.Join(root, "hoolicy.yaml"))
	if err != nil {
		t.Fatalf("load v0.1 project: %v", err)
	}
	if project.Version != 1 || project.Project != "v0-1-compatibility" || len(project.Rules) != 1 {
		t.Fatalf("unexpected v0.1 project: %#v", project)
	}

	pack, err := config.LoadPack(filepath.Join(root, "pack"))
	if err != nil {
		t.Fatalf("load v0.1 pack: %v", err)
	}
	if pack.Version != 1 || pack.Name != "legacy" || pack.Release != "0.1.0" || pack.Maturity != "experimental" {
		t.Fatalf("unexpected v0.1 pack: %#v", pack)
	}
	rules, err := pack.Instantiate(map[string]any{"required_file": "README.md"})
	if err != nil || len(rules) != 1 || len(rules[0].Files) != 1 || rules[0].Files[0] != "README.md" {
		t.Fatalf("instantiate v0.1 pack: rules=%#v err=%v", rules, err)
	}
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	kind, exists := registry.Kind(rules[0].Kind)
	if !exists {
		t.Fatalf("v0.1 rule kind %s disappeared", rules[0].Kind)
	}
	if err := kind.Validate(rules[0]); err != nil {
		t.Fatalf("validate v0.1 rule: %v", err)
	}
}
