package rules

import (
	"context"
	"testing"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestDependencyGovernanceChecksBlockAndQuotedGoReplacements(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "go.mod", `module example.com/app

go 1.26

replace (
 example.com/a => ../a // local replacement
 example.com/b v1.2.3 => "../b with spaces"
 example.com/allowed => ./allowed
 example.com/remote => example.com/fork v1.2.3
)
replace example.com/c => "./c"
// replace example.com/comment => ../ignored
`)
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("demo.dependencies", "dependency.governance", []string{"go.mod"}, map[string]any{"allowedLocalDependencies": []any{"example.com/allowed"}})
	findings, err := (DependencyGovernance{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 3 {
		t.Fatalf("expected three unapproved local replacement findings, got %#v", findings)
	}
	for index, want := range []string{"replace:example.com/a", "replace:example.com/b", "replace:example.com/c"} {
		if findings[index].Key != want {
			t.Fatalf("finding %d key=%s, want %s", index, findings[index].Key, want)
		}
	}
}
