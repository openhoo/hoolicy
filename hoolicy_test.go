package hoolicy

import "testing"

func TestNewRegistryContainsCoreKinds(t *testing.T) {
	t.Parallel()
	registry, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	if len(registry.Names()) != 14 {
		t.Fatalf("unexpected core kinds: %#v", registry.Names())
	}
}
