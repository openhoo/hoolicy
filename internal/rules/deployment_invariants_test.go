package rules

import (
	"context"
	"fmt"
	"testing"

	"github.com/openhoo/hoolicy/internal/repository"
	"github.com/openhoo/hoolicy/sdk"
)

func TestDeploymentResourceLimitsValidateWholeQuantity(t *testing.T) {
	t.Parallel()
	tests := []struct {
		platform string
		cpu      string
		memory   string
		valid    bool
	}{
		{"kubernetes", "250m", "128Mi", true},
		{"kubernetes", "+1", "1Gi", true},
		{"kubernetes", ".5", "1.5Gi", true},
		{"kubernetes", "1e-3", "1E6", true},
		{"kubernetes", "1.", "1k", true},
		{"kubernetes", "1bogus", "128Mi", false},
		{"kubernetes", "1GiJUNK", "128Mi", false},
		{"kubernetes", "1e", "128Mi", false},
		{"kubernetes", "1", "128MiJUNK", false},
		{"kubernetes", "1", "1K", false},
		{"kubernetes", "0e10", "128Mi", false},
		{"kubernetes", "-1", "128Mi", false},
		{"compose", "0.5", "128m", true},
		{"compose", "1", "1GB", true},
		{"compose", "1", "1024", true},
		{"compose", "1", ".5k", true},
		{"compose", "1", "1e3", true},
		{"compose", "1", "1e-3m", true},
		{"compose", "1", "0", false},
		{"compose", "1", "1e-3", false},
		{"compose", "1", ".5b", false},
		{"compose", "1", ".0001k", false},
		{"compose", "1bogus", "128m", false},
		{"compose", "250m", "128m", false},
		{"compose", "1", "128garbage", false},
		{"compose", "1", "128MBjunk", false},
		{"compose", "1", "1e", false},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%s/%s/%s", test.platform, test.cpu, test.memory), func(t *testing.T) {
			root := t.TempDir()
			body := fmt.Sprintf("kind: Pod\nspec:\n  containers:\n    - name: app\n      image: registry.example.com/app:v1\n      resources:\n        limits: {cpu: %q, memory: %q}\n", test.cpu, test.memory)
			if test.platform == "compose" {
				body = fmt.Sprintf("services:\n  app:\n    image: registry.example.com/app:v1\n    cpus: %q\n    mem_limit: %q\n", test.cpu, test.memory)
			}
			writeRuleFile(t, root, "deployment.yaml", body)
			repo, err := repository.Open(root, repository.Options{})
			if err != nil {
				t.Fatal(err)
			}
			rule := baseRule("smoke.resources", "deployment.invariants", []string{"deployment.yaml"}, map[string]any{"platform": test.platform, "requireResourceLimits": true})
			findings, err := (DeploymentInvariants{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
			if err != nil {
				t.Fatal(err)
			}
			if (len(findings) == 0) != test.valid {
				t.Fatalf("valid=%v, findings=%#v", test.valid, findings)
			}
		})
	}
}

func TestComposeResourceLimitsPreserveNumericValues(t *testing.T) {
	t.Parallel()
	for _, body := range []string{
		"services:\n  app:\n    image: registry.example.com/app:v1\n    cpus: 0.5\n    mem_limit: 134217728\n",
		"services:\n  app:\n    image: registry.example.com/app:v1\n    deploy:\n      resources:\n        limits: {cpus: 0.5, memory: 134217728}\n",
	} {
		root := t.TempDir()
		writeRuleFile(t, root, "compose.yaml", body)
		repo, err := repository.Open(root, repository.Options{})
		if err != nil {
			t.Fatal(err)
		}
		rule := baseRule("smoke.resources", "deployment.invariants", []string{"compose.yaml"}, map[string]any{"platform": "compose", "requireResourceLimits": true})
		findings, err := (DeploymentInvariants{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
		if err != nil || len(findings) != 0 {
			t.Fatalf("valid numeric resource limits rejected: findings=%#v err=%v", findings, err)
		}
	}
}

func TestComposeMemoryLimitRejectsFractionalNumericBytes(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	writeRuleFile(t, root, "compose.yaml", "services:\n  app:\n    image: registry.example.com/app:v1\n    cpus: 0.5\n    mem_limit: 0.5\n")
	repo, err := repository.Open(root, repository.Options{})
	if err != nil {
		t.Fatal(err)
	}
	rule := baseRule("smoke.resources", "deployment.invariants", []string{"compose.yaml"}, map[string]any{"platform": "compose", "requireResourceLimits": true})
	findings, err := (DeploymentInvariants{}).Evaluate(context.Background(), sdk.EvalContext{Repository: repo}, rule)
	if err != nil || len(findings) != 1 {
		t.Fatalf("effective zero-byte limit accepted: findings=%#v err=%v", findings, err)
	}
}
