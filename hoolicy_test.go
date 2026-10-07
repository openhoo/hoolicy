package hoolicy

import (
	"slices"
	"testing"
)

func TestNewRegistryContainsCoreKinds(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"api.contract", "artifact.evidence", "ci.workflow-security", "dependency.governance", "deployment.invariants", "exceptions.lifecycle", "files", "gherkin.requirements", "git.naming", "i18n.parity", "manifest.consistency", "sources.allowed", "structured.cel", "structured.fields", "text"}
	if !slices.Equal(registry.Names(), want) {
		t.Fatalf("unexpected core kinds: %#v", registry.Names())
	}
}
