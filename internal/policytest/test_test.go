package policytest

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/openhoo/hoolicy/internal/rules"
	"github.com/openhoo/hoolicy/sdk"
)

func TestBuiltInPacksHavePassingPositiveAndNegativeCases(t *testing.T) {
	t.Parallel()
	registry := sdk.NewRegistry()
	if err := rules.RegisterCore(registry); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"repository", "supply-chain", "product-quality"} {
		t.Run(name, func(t *testing.T) {
			result := Run(context.Background(), filepath.Join("..", "..", "packs", name), registry)
			if len(result.Errors) > 0 || result.Passed != result.Cases || result.Cases < 2 {
				t.Fatalf("unexpected pack test result: %#v", result)
			}
		})
	}
}
