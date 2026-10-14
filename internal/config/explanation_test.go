package config

import (
	"strings"
	"testing"

	"github.com/openhoo/hoolicy/sdk"
)

func TestPackExplanationsExpandAndRejectInvalidExpandedGuidance(t *testing.T) {
	t.Parallel()
	pack := &Pack{Name: "demo", Release: "1.0.0", Parameters: map[string]Parameter{"step": {Type: "string", Default: "Review the file", Description: "Action to describe"}}, Rules: []sdk.Rule{{ID: "demo.rule", Explanation: &sdk.Explanation{Steps: []string{"{{ step }}"}, Expectation: "Reviewed input"}}}}
	instantiated, err := pack.Instantiate(nil)
	if err != nil || instantiated[0].Explanation.Steps[0] != "Review the file" {
		t.Fatalf("pack guidance was not expanded: %v", err)
	}
	if _, err := pack.Instantiate(map[string]any{"step": ""}); err == nil || !strings.Contains(err.Error(), "explanation.steps[0]") {
		t.Fatalf("invalid expanded guidance admitted: %v", err)
	}
	instantiated[0].Explanation.Steps[0] = "changed"
	if pack.Rules[0].Explanation.Steps[0] != "{{ step }}" {
		t.Fatal("instantiation mutated source guidance")
	}
}
